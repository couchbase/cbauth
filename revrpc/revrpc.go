// @author Couchbase <info@couchbase.com>
// @copyright 2014 Couchbase, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package revrpc provides jsonrpc library that matches ns_server's
// json_rpc_connection module. It allows golang service to connect to
// ns_server and receive jsonrpc requests via that connection.
package revrpc

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/rpc"
	"net/rpc/jsonrpc"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/couchbase/cbauth/utils"
	log "github.com/couchbase/clog"
)

// ServiceSetupCallback type defines functions that can be passed to
// Run and to BabysitService. Function is expected to register
// "rpc-exported" object instances with given rpc server.
type ServiceSetupCallback func(server *rpc.Server) error

type serviceImpl interface {
	Run(setupBody ServiceSetupCallback) error
}

// Service type represents specific configured instance of revrpc.
type Service struct {
	l       sync.Mutex
	running int32
	user    string
	pwd     string
	url     *url.URL
	codec   *jsonServerCodec
	stopped bool
}

type HttpError struct {
	StatusCode int
	Message    string
}

func (e *HttpError) Error() string {
	return fmt.Sprintf("Need 200 status!. Got %v %v",
		e.StatusCode, e.Message)
}

// ErrAlreadyRunning is returned from Run method to indicate that
// given Service instance is already running.
var ErrAlreadyRunning = errors.New("service is already running")
var ErrRevRpcUnauthorized = errors.New("invalid revrpc credentials")

const uaSvcSuffix = "service"
const uaSvcVersion = ""

var userAgent = utils.MakeUserAgent(uaSvcSuffix, uaSvcVersion)

// NewService creates and returns Service instance that connects to
// given ns_server url (which is expected to have creds
// encoded). Returns error if url is malformed. Does not actually
// connect to ns_server, so it will succeed even if ns_server is not
// running or if creds are not valid admin creds.
func NewService(connectURL string) (*Service, error) {
	u, err := url.Parse(connectURL)
	if err != nil {
		// TODO: nicer error maybe
		return nil, err
	}
	user := ""
	pwd := ""
	if ui := u.User; ui != nil {
		user = ui.Username()
		pwd, _ = ui.Password()
	}

	return &Service{
		user:    user,
		pwd:     pwd,
		url:     u,
		stopped: false,
	}, nil
}

// MustService is like NewService except that it panics on
// errors. I.e. it is useful in cases where errors are not expected.
func MustService(connectURL string) *Service {
	rv, err := NewService(connectURL)
	if err != nil {
		panic(err)
	}
	return rv
}

type minirwc struct {
	net.Conn
	bufreader *bufio.Reader
}

func (r *minirwc) Read(buf []byte) (n int, err error) {
	return r.bufreader.Read(buf)
}

type jsonServerCodec struct {
	rpc.ServerCodec
}

func newJsonServerCodec(conn io.ReadWriteCloser) *jsonServerCodec {
	return &jsonServerCodec{jsonrpc.NewServerCodec(conn)}
}

func (c *jsonServerCodec) WriteResponse(r *rpc.Response, x interface{}) error {
	err := c.ServerCodec.WriteResponse(r, x)

	// net/rpc drops any errors returned by WriteResponse on the floor:
	// https://cs.opensource.google/go/go/+/refs/tags/go1.17:src/net/rpc/server.go;drc=b83d073e9eb4cbd0cd5ca530f576668c49f6d0f1;l=353-356.
	//
	// This is probably fine for IO errors like the connection being
	// closed. But if it's the case that we tried encoding to json
	// something that can't be encoded, ns_server will keep waiting for a
	// response. In addition, diagnosing what caused the encoding error is
	// quite challenging in these cases. So we just panic on any json
	// encoding errors to catch these cases as early as possible.
	//
	// See MB-47600 for more details.
	if c.isEncodingError(err) {
		panic(fmt.Errorf("Failed to encode revrpc response: %s\n"+
			"Response:\n%v",
			err.Error(), x))
	}

	return err
}

func (c *jsonServerCodec) isEncodingError(err error) bool {
	switch err.(type) {
	case *json.UnsupportedTypeError:
		return true
	case *json.UnsupportedValueError:
		return true
	case *json.MarshalerError:
		return true
	default:
		return false
	}
}

type RevrpcSvc struct {
	service *Service
}

type URLChange struct {
	NewURL string `json:"newURL"`
}

type URLChangeResult struct {
	IsSucc      bool   `json:"isSucc"`
	Description string `json:"description"`
}

func (s *RevrpcSvc) UpdateURL(urlChange URLChange, res *URLChangeResult) error {
	rv := MustService(urlChange.NewURL)
	req, _ := http.NewRequest("RPCCONNECT", rv.url.String()+"/test", nil)
	req.SetBasicAuth(rv.user, rv.pwd)
	req.Header.Set("User-Agent", userAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		*res = URLChangeResult{IsSucc: false, Description: err.Error()}
		return nil
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		err = fmt.Errorf(
			"test RPCCONNECT failed: need 200 status!. Got %v",
			resp.StatusCode)
		print(err)
		*res = URLChangeResult{IsSucc: false, Description: err.Error()}
		return nil
	}

	s.service.url = rv.url
	s.service.user = rv.user
	s.service.pwd = rv.pwd
	*res = URLChangeResult{IsSucc: true, Description: ""}
	return nil
}

// Run method connects to ns_server, sets up json rpc instance and
// handles rpc requests loop until connection is alive. Returned error
// is always non-nil. In case connection was closed by ns_server
// io.EOF is returned.
func (s *Service) Run(setupBody ServiceSetupCallback) error {
	if !atomic.CompareAndSwapInt32(&s.running, 0, 1) {
		return ErrAlreadyRunning
	}
	defer func() {
		atomic.StoreInt32(&s.running, 0)
	}()

	s.l.Lock()
	if s.stopped {
		s.l.Unlock()
		return io.EOF
	}
	s.l.Unlock()

	conn, err := net.Dial("tcp", s.url.Host)
	if err != nil {
		return err
	}
	defer conn.Close()

	conn.(*net.TCPConn).SetNoDelay(true)

	req, _ := http.NewRequest("RPCCONNECT", s.url.String(), nil)
	req.SetBasicAuth(s.user, s.pwd)
	req.Header.Set("User-Agent", userAgent)
	err = req.Write(conn)
	if err != nil {
		return err
	}
	connr := bufio.NewReader(conn)
	rwc := &minirwc{Conn: conn, bufreader: connr}
	resp, err := http.ReadResponse(connr, req)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		if resp.StatusCode == 401 {
			return ErrRevRpcUnauthorized
		}
		var message = ""
		if resp.StatusCode == 400 {
			body, err := ioutil.ReadAll(resp.Body)
			if err == nil {
				message = string(body)
			}
			resp.Body.Close()
		}
		return &HttpError{StatusCode: resp.StatusCode, Message: message}
	}

	rpcServer := rpc.NewServer()
	err = setupBody(rpcServer)
	rpcServer.RegisterName("revrpc", &RevrpcSvc{service: s})
	if err != nil {
		return err
	}

	codec := newJsonServerCodec(rwc)

	s.l.Lock()
	if s.stopped {
		codec.Close()
		s.l.Unlock()
		return io.EOF
	}
	s.codec = codec
	s.l.Unlock()

	rpcServer.ServeCodec(codec)

	return io.EOF
}

func (s *Service) Disconnect() error {
	s.l.Lock()
	defer s.l.Unlock()
	if s.codec == nil {
		s.stopped = true
		return nil
	}
	err := s.codec.Close()
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			// ignore this error
		} else {
			return err
		}
	}
	s.codec = nil
	s.stopped = true
	return nil
}

// ErrorPolicyFn function is used to make error handling decision in
// BabysitService. Function returns nil to "eat" error and case
// BabysitService to restart Service. Otherwise, returned error
// provides return value for BabysitService invocation.
type ErrorPolicyFn func(err error) error

// BabysitErrorPolicy represents error handling policy.
type BabysitErrorPolicy interface {
	// New method is expected to initialize and return
	// ErrorPolicyFn instance. That instance will be used by
	// BabysitService invocation until ErrorPolicyFn returns
	// non-nil error.
	New() ErrorPolicyFn
}

// DefaultErrorPolicy is default configurable implementation of
// BabysitErrorPolicy.
type DefaultErrorPolicy struct {
	// RestartsToExit determines how many restarts this error
	// policy will do before giving up. Negative value means
	// restart infinitely.
	RestartsToExit int
	// SleepBetweenRestarts specifies duration to sleep between
	// restarts.
	SleepBetweenRestarts time.Duration
	// LogPrint function, if non-nil, is used by
	// DefaultErrorPolicy to log it's events & decisions.
	// log.Print function is one suitable implementation.
	LogPrint     func(args ...interface{})
	restartsLeft int
}

// DefaultBabysitErrorPolicy is BabysitErrorPolicy instance that is
// used by default. It's initial value is "suitably configured"
// DefaultErrorPolicy instance.
var DefaultBabysitErrorPolicy BabysitErrorPolicy = DefaultErrorPolicy{
	RestartsToExit:       -1,
	SleepBetweenRestarts: time.Second,
	LogPrint:             log.Print,
}

func (p *DefaultErrorPolicy) try(err error) error {
	if err == ErrRevRpcUnauthorized {
		return err
	}
	if p.RestartsToExit >= 0 {
		p.restartsLeft--
		if p.restartsLeft <= 0 {
			if err == nil {
				err = errors.New("Retries exceeded")
			}
			p.LogPrint("Will not retry on error: ", err)
			return err
		}
	}

	p.LogPrint(fmt.Sprintf("revrpc: Got error (%s) and will retry in %s", err, p.SleepBetweenRestarts))
	time.Sleep(p.SleepBetweenRestarts)

	return nil
}

// New method of DefaultErrorPolicy implements New method of
// BabysitErrorPolicy interface. It returns ErrorPolicyFn that will
// allow configured number of restarts and will sleep configured
// duration between restarts.
func (p DefaultErrorPolicy) New() ErrorPolicyFn {
	// NOTE: that p is _copy_ of policy instance
	p.restartsLeft = p.RestartsToExit
	return (&p).try
}

// FnBabysitErrorPolicy type adapts ErrorPolicyFn to
// BabysitErrorPolicy interface.
type FnBabysitErrorPolicy ErrorPolicyFn

// New method simply returns "this" function.
func (p FnBabysitErrorPolicy) New() ErrorPolicyFn {
	return ErrorPolicyFn(p)
}

// NoRestartsBabysitErrorPolicy is error policy that always forbids restarts.
var NoRestartsBabysitErrorPolicy BabysitErrorPolicy = FnBabysitErrorPolicy(func(err error) error { return err })

// BabysitService function runs given service instance, restarting it
// as needed if allowed by given BabysitErrorPolicy. nil
// can be passed to errorPolicy argument, in which case value of
// DefaultBabysitErrorPolicy is used.
func BabysitService(setupBody ServiceSetupCallback, svc *Service, errorPolicy BabysitErrorPolicy) error {
	if errorPolicy == nil {
		errorPolicy = DefaultBabysitErrorPolicy
	}
	errorFn := errorPolicy.New()
	for {
		err := errorFn(svc.Run(setupBody))
		if err != nil {
			return err
		}
	}
}

func doGetServiceFromEnv(serviceName string) (*Service, error) {
	rurl := os.Getenv("CBAUTH_REVRPC_URL")
	if rurl == "" {
		return nil, fmt.Errorf("cbauth environment variable " +
			"CBAUTH_REVRPC_URL is not set")
	}

	u, err := url.Parse(rurl)
	if err != nil {
		return nil, fmt.Errorf("cbauth environment variable "+
			"CBAUTH_REVRPC_URL is malformed. "+
			"Parsing it failed with: %s", err)
	}

	u.Path = u.Path + "-" + serviceName
	surl := u.String()

	// parsing url cannot fail due to way it was constructed.
	return MustService(surl), nil
}

var defaultsGot = make(map[string]bool)
var defaultsGotL sync.Mutex

// GetDefaultServiceFromEnv returns Service instance that connects to
// ns_server according to CBAUTH_REVRPC_URL environment variable. Trying to
// obtain same service twice will return error. I.e. you're supposed to get
// your Service instance once and only once and hold it forever.
func GetDefaultServiceFromEnv(serviceName string) (*Service, error) {
	defaultsGotL.Lock()
	defer defaultsGotL.Unlock()
	if defaultsGot[serviceName] {
		return nil, fmt.Errorf("Service `%s' was already obtained (and presumably started)", serviceName)
	}
	svc, err := doGetServiceFromEnv(serviceName)
	if err == nil {
		defaultsGot[serviceName] = true
	}
	return svc, err
}
