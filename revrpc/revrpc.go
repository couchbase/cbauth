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
// ns_server and recieve jsonrpc requests via that connection.
package revrpc

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/rpc"
	"net/rpc/jsonrpc"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"
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
	running int32
	user    string
	pwd     string
	url     *url.URL
}

// ErrAlreadyRunning is returned from Run method to indicate that
// given Service instance is already running.
var ErrAlreadyRunning = errors.New("service is already running")

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
		user: user,
		pwd:  pwd,
		url:  u,
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

	conn, err := net.Dial("tcp", s.url.Host)
	if err != nil {
		return err
	}
	defer conn.Close()

	conn.(*net.TCPConn).SetNoDelay(true)

	req, _ := http.NewRequest("RPCCONNECT", s.url.String(), nil)
	req.SetBasicAuth(s.user, s.pwd)
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
		return fmt.Errorf("Need 200 status!. Got %v", *resp)
	}

	rpcServer := rpc.NewServer()
	err = setupBody(rpcServer)
	if err != nil {
		return err
	}

	codec := jsonrpc.NewServerCodec(rwc)
	rpcServer.ServeCodec(codec)

	return io.EOF
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
	if rurl := os.Getenv("CBAUTH_REVRPC_URL"); rurl != "" {
		return NewService(rurl)
	}

	surl := os.Getenv("NS_SERVER_CBAUTH_RPC_URL")
	user := os.Getenv("NS_SERVER_CBAUTH_USER")
	pwd := os.Getenv("NS_SERVER_CBAUTH_PWD")
	if surl == "" || user == "" || pwd == "" {
		return nil, fmt.Errorf("Some cbauth environment variables are not set. I.e.: (rpc-url: `%s', user: `%s', pwd: `%s')", surl, user, pwd)
	}
	u, err := url.Parse(surl)
	if err != nil {
		return nil, fmt.Errorf("cbauth environment variable NS_SERVER_CBAUTH_RPC_URL is malformed. Parsing it failed with: %s", err)
	}
	u.User = url.UserPassword(user, pwd)
	u.Path = u.Path + "-" + serviceName
	surl = u.String()

	// parsing url cannot fail due to way it was constructed.
	return MustService(surl), nil
}

var defaultsGot = make(map[string]bool)
var defaultsGotL sync.Mutex

// GetDefaultServiceFromEnv returns Service instance that connects to
// ns_server according to CBAUTH_REVRPC_URL environment variable (or
// backwards compat variables NS_SERVER_CBAUTH_{RPC_URL,USER,PWD}
// ). serviceName should be unique name of your revrpc service. cbauth
// itself is using serviceName = "cbauth". Trying to obtain same
// service twice will return error. I.e. you're supposed to get your
// Service instance once and only once and hold it forever.
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
