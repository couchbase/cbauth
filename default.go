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

package cbauth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/rpc"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/couchbase/cbauth/cbauthimpl"
	"github.com/couchbase/cbauth/httpreq"
	"github.com/couchbase/cbauth/revrpc"
	"github.com/couchbase/clog"
)

// Default variable holds default authenticator. Default authenticator
// is constructed automatically from environment variables passed by
// ns_server. It is nil if your process was not (correctly) spawned by
// ns_server.
var Default Authenticator

type restartableAuthImpl struct {
	l sync.RWMutex
	a ExternalAuthenticator
	s *revrpc.Service
}

func (r *restartableAuthImpl) getAuth() ExternalAuthenticator {
	r.l.RLock()
	defer r.l.RUnlock()
	return r.a
}

func (r *restartableAuthImpl) setAuth(a ExternalAuthenticator,
	s *revrpc.Service) {
	r.l.Lock()
	defer r.l.Unlock()
	r.a = a
	r.s = s
}

func (r *restartableAuthImpl) disconnect() error {
	r.l.Lock()
	defer r.l.Unlock()

	if r.s == nil {
		return nil
	}

	err := r.s.Disconnect()
	if err != nil {
		return err
	}
	r.s = nil
	return nil
}

var externalAuth = restartableAuthImpl{}

var errDisconnected = errors.New("revrpc connection to ns_server was closed")
var errUnrecoverable = errors.New("revrpc connection cannot be established")

const waitBeforeStale = time.Minute

func getCbauthErrorPolicy(svc *cbauthimpl.Svc,
	external bool) revrpc.ErrorPolicyFn {

	if external {
		defPolicy := getCbauthErrorPolicy(svc, false)
		return func(err error) error {
			if err == io.EOF {
				cbauthimpl.ResetSvc(svc, &DBStaleError{err})
				return errDisconnected
			}
			httpErr, ok := err.(*revrpc.HttpError)
			if ok &&
				httpErr.StatusCode == 400 &&
				httpErr.Message == "Version is not supported" {
				cbauthimpl.ResetSvc(svc, &DBStaleError{err})
				return errUnrecoverable
			}
			return defPolicy(err)
		}
	} else {
		defPolicy := revrpc.DefaultBabysitErrorPolicy.New()
		// error restart policy that we're going to use simply
		// resets service before delegating to default restart
		// policy. That way we always mark service as stale
		// right after some error occurred.
		return func(err error) error {
			cbauthimpl.ResetSvc(svc, &DBStaleError{err})
			return defPolicy(err)
		}
	}
}

func runRPCForSvc(rpcsvc *revrpc.Service, svc *cbauthimpl.Svc,
	policy revrpc.ErrorPolicyFn) error {
	return revrpc.BabysitService(func(s *rpc.Server) error {
		return s.RegisterName("AuthCacheSvc", svc)
	}, rpcsvc, revrpc.FnBabysitErrorPolicy(policy))
}

func startDefault(rpcsvc *revrpc.Service, svc *cbauthimpl.Svc,
	policy revrpc.ErrorPolicyFn, external bool) {
	if external {
		externalAuth.setAuth(&authImpl{svc}, rpcsvc)
	} else {
		Default = &authImpl{svc}
	}
	go func() {
		err := runRPCForSvc(rpcsvc, svc, policy)
		if errors.Is(err, errDisconnected) ||
			errors.Is(err, errUnrecoverable) {
			return
		}
		panic(err)
	}()
}

func init() {
	rpcsvc, err := revrpc.GetDefaultServiceFromEnv("cbauth")
	if err != nil {
		ErrNotInitialized = fmt.Errorf("Unable to initialize cbauth's revrpc: %s", err)
		return
	}
	svc := newSvc()
	startDefault(rpcsvc, svc, getCbauthErrorPolicy(svc, false), false)
}

func newSvc() *cbauthimpl.Svc {
	return cbauthimpl.NewSVC(waitBeforeStale, &DBStaleError{})
}

// InitExternal should be used by external cbauth client to enable cbauth
// with limited functionality.
func InitExternal(service, mgmtHostPort, user, password string) error {
	return InitExternalWithHeartbeat(service, mgmtHostPort, user, password,
		0, 0)
}

// InitExternalWithHeartbeat should be used by external cbauth client to enable
// cbauth with limited functionality and enabling heartbeats.
// heartbeatInterval - interval in seconds at which heartbeats should be sent
// heartbeatWait - defines how many seconds we wait until declaring the
// database stale
func InitExternalWithHeartbeat(service, mgmtHostPort, user, password string,
	heartbeatInterval, heartbeatWait int) error {
	err := externalAuth.disconnect()
	if err != nil {
		clog.Warnf("failed to disconnect existing external authenticator: %s", err)
	}
	_, err = doInternalRetryDefaultInitWithService(service,
		mgmtHostPort, user, password, true, heartbeatInterval,
		heartbeatWait)
	return err
}

// InternalRetryDefaultInit can be used by golang services that are
// willing to perform manual initialization of cbauth (i.e. for easier
// testing). This API is subject to change and should be used only if
// really needed. Returns false if Default Authenticator was already
// initialized.
func InternalRetryDefaultInit(mgmtHostPort, user, password string) (bool, error) {
	service := filepath.Base(os.Args[0])
	return InternalRetryDefaultInitWithService(service, mgmtHostPort, user, password)
}

// InternalRetryDefaultInitWithService can be used by golang services that are
// willing to perform manual initialization of cbauth (i.e. for easier
// testing). This API is subject to change and should be used only if
// really needed. Returns false if Default Authenticator was already
// initialized.
func InternalRetryDefaultInitWithService(service, mgmtHostPort, user, password string) (bool, error) {
	if Default != nil {
		return false, nil
	}
	return doInternalRetryDefaultInitWithService(service+"-cbauth",
		mgmtHostPort, user, password, false, 0, 0)
}

func doInternalRetryDefaultInitWithService(
	service, mgmtHostPort, user, password string,
	external bool, heartbeatInterval, heartbeatWait int) (bool, error) {
	host, port, err := SplitHostPort(mgmtHostPort)
	if err != nil {
		return false, fmt.Errorf("Failed to split hostport `%s': %s", mgmtHostPort, err)
	}
	var baseurl string
	if external {
		baseurl = fmt.Sprintf("http://%s:%d/auth/v1/%s",
			host, port, service)
	} else {
		baseurl = fmt.Sprintf("http://%s:%d/%s", host, port, service)
	}
	if heartbeatInterval != 0 {
		baseurl = baseurl + fmt.Sprintf("?heartbeat=%v",
			heartbeatInterval)
	}
	u, err := url.Parse(baseurl)
	if err != nil {
		return false, fmt.Errorf("Failed to parse constructed url `%s': %s", baseurl, err)
	}
	u.User = url.UserPassword(user, password)

	svc := newSvc()
	svc.SetConnectInfo(mgmtHostPort, user, password, heartbeatInterval,
		heartbeatWait)

	startDefault(revrpc.MustService(u.String()), svc,
		getCbauthErrorPolicy(svc, external), external)

	return true, nil
}

// ErrNotInitialized is used to signal that ns_server environment
// variables are not set, and thus Default authenticator is not
// configured for calls that use default authenticator.
var ErrNotInitialized = errors.New("cbauth was not initialized")

// WithDefault calls given body with default authenticator. If default
// authenticator is not configured, it returns ErrNotInitialized.
func WithDefault(body func(a Authenticator) error) error {
	return WithAuthenticator(nil, body)
}

// WithAuthenticator calls given body with either passed authenticator
// or default authenticator if `a' is nil. ErrNotInitialized is
// returned if a is nil and default authenticator is not configured.
func WithAuthenticator(a Authenticator, body func(a Authenticator) error) error {
	if a == nil {
		a = Default
		if a == nil {
			return ErrNotInitialized
		}
	}
	return body(a)
}

func GetExternalAuthenticator() ExternalAuthenticator {
	return externalAuth.getAuth()
}

// AuthWebCreds method extracts credentials from given http request
// using default authenticator.
func AuthWebCreds(req *http.Request) (creds Creds, err error) {
	if Default == nil {
		return nil, ErrNotInitialized
	}
	return Default.AuthWebCreds(req)
}

// AuthWebCredsGeneric method extracts credentials from an HTTP request
// that is generic (not necessarily using the net/http library)
func AuthWebCredsGeneric(req httpreq.HttpRequest) (creds Creds, err error) {
	if Default == nil {
		return nil, ErrNotInitialized
	}
	return Default.AuthWebCredsGeneric(req)
}

// Auth method constructs credentials from given user and password
// pair. Uses default authenticator.
func Auth(user, pwd string) (creds Creds, err error) {
	if Default == nil {
		return nil, ErrNotInitialized
	}
	return Default.Auth(user, pwd)
}

// GetHTTPServiceAuth returns user/password creds giving "admin"
// access to given http service inside couchbase cluster. Uses default
// authenticator.
func GetHTTPServiceAuth(hostport string) (user, pwd string, err error) {
	if Default == nil {
		return "", "", ErrNotInitialized
	}
	return Default.GetHTTPServiceAuth(hostport)
}

// GetMemcachedServiceAuth returns user/password creds given "admin"
// access to given memcached service. Uses default authenticator.
func GetMemcachedServiceAuth(hostport string) (user, pwd string, err error) {
	if Default == nil {
		return "", "", ErrNotInitialized
	}
	return Default.GetMemcachedServiceAuth(hostport)
}

// RegisterTLSRefreshCallback registers a callback to be called when any field
// of TLS settings change. The callback is called in separate routine
func RegisterTLSRefreshCallback(callback TLSRefreshCallback) error {
	if Default == nil {
		return ErrNotInitialized
	}
	Default.RegisterTLSRefreshCallback(callback)
	return nil
}

func RegisterConfigRefreshCallback(callback ConfigRefreshCallback) error {
	if Default == nil {
		return ErrNotInitialized
	}
	Default.RegisterConfigRefreshCallback(callback)
	return nil
}

// GetClientCertAuthType returns TLS cert type
func GetClientCertAuthType() (tls.ClientAuthType, error) {
	if Default == nil {
		return tls.NoClientCert, ErrNotInitialized
	}
	return Default.GetClientCertAuthType()
}

func GetClusterEncryptionConfig() (ClusterEncryptionConfig, error) {
	if Default == nil {
		return ClusterEncryptionConfig{}, ErrNotInitialized
	}

	return Default.GetClusterEncryptionConfig()
}

func GetUserUuid(user, domain string) (string, error) {
	if Default == nil {
		return "", ErrNotInitialized
	}

	return Default.GetUserUuid(user, domain)
}

func GetUserBuckets(user, domain string) ([]string, error) {
	if Default == nil {
		return []string{}, ErrNotInitialized
	}

	return Default.GetUserBuckets(user, domain)
}

func GetGuardrailStatuses() (GuardrailStatuses, error) {
	if Default == nil {
		return GuardrailStatuses{}, ErrNotInitialized
	}
	return Default.GetGuardrailStatuses()
}

// GetTLSConfig returns current tls config that contains cipher suites,
// min TLS version, etc.
func GetTLSConfig() (TLSConfig, error) {
	if Default == nil {
		return TLSConfig{}, ErrNotInitialized
	}
	return Default.GetTLSConfig()
}

func RegisterEncryptionKeysCallbacks(refreshKeysCallback RefreshKeysCallback, getInUseKeysCallback GetInUseKeysCallback, dropKeysCallback DropKeysCallback) error {
	if Default == nil {
		return ErrNotInitialized
	}
	Default.RegisterEncryptionKeysCallbacks(refreshKeysCallback, getInUseKeysCallback, dropKeysCallback)
	return nil
}

func GetEncryptionKeys(key KeyDataType) (*EncrKeysInfo, error) {
	if Default == nil {
		return nil, ErrNotInitialized
	}
	return Default.GetEncryptionKeys(key)
}

func KeysDropComplete(key KeyDataType, dropErr error) error {
	if Default == nil {
		return ErrNotInitialized
	}
	return Default.KeysDropComplete(key, dropErr)
}

func GetEncryptionKeysBlocking(ctx context.Context, key KeyDataType) (*EncrKeysInfo, error) {
	if Default == nil {
		return nil, ErrNotInitialized
	}
	return Default.GetEncryptionKeysBlocking(ctx, key)
}
