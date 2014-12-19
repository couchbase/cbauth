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
	serviceImpl
}

// Run method connects to ns_server, sets up json rpc instance and
// handles rpc requests loop until connection is alive. Returned error
// is always non-nil. In case connection was closed by ns_server
// io.EOF is returned.
func (s *Service) Run(setupBody ServiceSetupCallback) error {
	return s.serviceImpl.Run(setupBody)
}

// ErrAlreadyRunning is returned from Run method to indicate that
// given Service instance is already running.
var ErrAlreadyRunning = errors.New("service is already running")

type defaultServiceImpl struct {
	running int32
	user    string
	pwd     string
	url     *url.URL
}

// NewDefaultService creates and returns Service instance that
// connects to given ns_server url using given credentials. Returns
// error if url is malformed. Does not actually connect to ns_server,
// so it will succeed even if ns_server is not running or if creds are
// not valid admin creds.
func NewDefaultService(user, pwd, connectURL string) (*Service, error) {
	u, err := url.Parse(connectURL)
	if err != nil {
		// TODO: nicer error maybe
		return nil, err
	}
	impl := &defaultServiceImpl{
		user: user,
		pwd:  pwd,
		url:  u,
	}
	return &Service{impl}, nil
}

type minirwc struct {
	net.Conn
	bufreader *bufio.Reader
}

func (r *minirwc) Read(buf []byte) (n int, err error) {
	return r.bufreader.Read(buf)
}

func (s *defaultServiceImpl) Run(setupBody ServiceSetupCallback) error {
	// TODO: consider nicer errors. Maybe via net.OpError
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

// ErrCBAuthServiceUnconfigured error is returned from Run method of
// Service returned by GetServiceFromEnv() if needed environment are
// not set.
var ErrCBAuthServiceUnconfigured = errors.New("cbauth service configuration environment variables not set")

var cbauthServiceOnce sync.Once
var cbauthService *Service
var cbauthServiceErr error

type errServiceImpl struct{ error }

func (e errServiceImpl) Run(setupBody ServiceSetupCallback) error {
	return e.error
}

// GetServiceFromEnv returns service instance that is configured from
// environment variables that are typically set by ns_server. This is
// default way to obtain Service instance for Couchbase golang
// services.
func GetServiceFromEnv() *Service {
	cbauthServiceOnce.Do(func() {
		connectURL := os.Getenv("NS_SERVER_CBAUTH_RPC_URL")
		authU := os.Getenv("NS_SERVER_CBAUTH_USER")
		authP := os.Getenv("NS_SERVER_CBAUTH_PWD")
		if connectURL == "" {
			cbauthServiceErr = ErrCBAuthServiceUnconfigured
			return
		}
		cbauthService, cbauthServiceErr = NewDefaultService(authU, authP, connectURL)
	})

	if cbauthService != nil {
		return cbauthService
	}

	return &Service{errServiceImpl{cbauthServiceErr}}
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
	// policy will do before giving up.
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
	RestartsToExit:       16,
	SleepBetweenRestarts: time.Second,
	LogPrint:             log.Print,
}

func (p *DefaultErrorPolicy) try(err error) error {
	if err == ErrCBAuthServiceUnconfigured {
		p.LogPrint(fmt.Sprintf("RevRpc connection was not started: %s.", err))
		return err
	}
	p.restartsLeft--
	if p.restartsLeft <= 0 {
		if err == nil {
			err = errors.New("Retries exceeded")
		}
		p.LogPrint("Will not retry on error: ", err)
		return err
	}

	p.LogPrint(fmt.Sprintf("Got error (%s) and will retry in %s", err, p.SleepBetweenRestarts))
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

// BabysitService function runs given service instance, restarting
// it as needed if allowed by given BabysitErrorPolicy. nil can be
// passed as Service instance, in which case Service from
// GetServiceFromEnv() function is used. Similarly, nil can be passed
// to errorPolicy argument, in which case value of
// DefaultBabysitErrorPolicy is used.
func BabysitService(setupBody ServiceSetupCallback, svc *Service, errorPolicy BabysitErrorPolicy) error {
	if svc == nil {
		svc = GetServiceFromEnv()
	}
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
