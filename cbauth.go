// @author Couchbase <info@couchbase.com>
// @copyright 2014-2023 Couchbase, Inc.
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

// Package cbauth provides auth{N,Z} for couchbase server services.
package cbauth

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/couchbase/cbauth/cbauthimpl"
	"github.com/couchbase/cbauth/httpreq"
)

// TODO: consider API that would allow us to do digest auth behind the
// scene

// TODO: for GetHTTPServiceAuth consider something more generic such
// as GetHTTPAuthHeader. Or even maybe RoundTrip. So that we can
// handle digest auth

// TLSRefreshCallback type describes callback for reinitializing TLSConfig when ssl certificate
// or client cert auth setting changes.
type TLSRefreshCallback cbauthimpl.TLSRefreshCallback

// The following constants are used as flags to indicate which configuration
// has changed. These flags are passed as an argument to 'ConfigRefreshcallback'
// function registered using the 'RegisterConfigRefreshCallback' API.
const (
	CFG_CHANGE_CERTS_TLSCONFIG uint64 = 1 << iota
	CFG_CHANGE_CLUSTER_ENCRYPTION
	CFG_CHANGE_CLIENT_CERTS_TLSCONFIG
	CFG_CHANGE_GUARDRAIL_STATUSES
)

// ConfigRefreshCallback type describes the callback that is called when there is
// a change in SSL certificates or TLS Config or cluster encryption config.
type ConfigRefreshCallback cbauthimpl.ConfigRefreshCallback

// TLSConfig contains tls settings to be used by cbauth clients
// When something in tls config changes user is notified via TLSRefreshCallback
type TLSConfig cbauthimpl.TLSConfig

// ClusterEncryptionConfig contains info about whether to use SSL ports for
// communication channels and whether to disable non-SSL ports.
type ClusterEncryptionConfig cbauthimpl.ClusterEncryptionConfig

// GuardrailStatuses contains a list of any currently breached guardrails, with
// their severities. Only guardrails applicable to the service will be included
type GuardrailStatuses []cbauthimpl.GuardrailStatus

type BaseAuthenticator interface {
	// AuthWebCreds method extracts credentials from given http request.
	AuthWebCreds(req *http.Request) (creds Creds, err error)
	// AuthWebCredsGeneric method extracts credentials from an HTTP request
	// that is generic (not necessarily using the net/http library)
	AuthWebCredsGeneric(req httpreq.HttpRequest) (creds Creds, err error)
	// Auth method constructs credentials from given user and password pair.
	Auth(user, pwd string) (creds Creds, err error)
	// GetHTTPServiceAuth returns user/password creds giving
	// "admin" access to given http service inside couchbase cluster.
}

// ExternalAuthenticator is cbauth interface for external clients. It supports
// only incoming auth.
type ExternalAuthenticator interface {
	BaseAuthenticator
	// GetNodeUuid returns UUID of the node cbauth is currently connecting to
	GetNodeUuid() (string, error)
	// GetClusterUuid returns UUID of the cluster cbauth is currently
	// connecting to
	GetClusterUuid() (string, error)
	// SetExpectedClusterUuid sets the UUID we expect the cluster to be
	SetExpectedClusterUuid(clusterUUID string) error
}

// Authenticator is main cbauth interface. It supports both incoming
// and outgoing auth.
type Authenticator interface {
	BaseAuthenticator
	GetHTTPServiceAuth(hostport string) (user, pwd string, err error)
	// GetMemcachedServiceAuth returns user/password creds given
	// "admin" access to given memcached service.
	GetMemcachedServiceAuth(hostport string) (user, pwd string, err error)
	// RegisterTLSRefreshCallback registers callback for refreshing TLS Config whenever
	// SSL certificates are refreshed or when client certificate auth state is changed.
	// Deprecated: Use RegisterConfigRefreshCallback instead.
	RegisterTLSRefreshCallback(callback TLSRefreshCallback) error
	// RegisterConfigRefreshCallback registers a callback function that will
	// be called whenever there is a change in certificates, TLS config or
	// cluster encryption settings.
	RegisterConfigRefreshCallback(callback ConfigRefreshCallback) error
	// GetClientCertAuthType returns the client certificate authentication
	// type to be used by the web-server.
	// Deprecated: Use cbauth.GetTLSConfig() instead.
	GetClientCertAuthType() (tls.ClientAuthType, error)
	// GetClusterEncryptionConfig returns ClusterEncryptionConfig which indicates
	// whether the client should used SSL ports for communication and whether
	// the unencrypted (non-SSL) ports should be disabled.
	GetClusterEncryptionConfig() (ClusterEncryptionConfig, error)
	// GetTLSConfig returns TLSConfig structure which includes cipher suites,
	// min tls version, etc.
	GetTLSConfig() (TLSConfig, error)
	// GetUserUuid returns uuid for a user.
	GetUserUuid(user, domain string) (string, error)
	// GetUserBuckets returns buckets on which a user has any of the
	// following permissions to:
	// - Access documents in any collection in the bucket
	// - Access collections metadata for any scope in the bucket
	GetUserBuckets(user, domain string) ([]string, error)
	GetGuardrailStatuses() (GuardrailStatuses, error)
}

// Creds type represents credentials and answers queries on this creds
// authorized actions. Note: it'll become (possibly much) wider API in
// future, but it's main purpose right now is to get us started.
type Creds interface {
	// Name method returns user name (e.g. for auditing)
	Name() string
	// Domain method returns user domain (for auditing)
	Domain() string
	// User method returns user and domain for non auditing purpose.
	User() (name, domain string)
	// IsAllowed method returns true if the permission is granted
	// for these credentials
	IsAllowed(permission string) (bool, error)
	// IsAllowedInternal method returns true if the permission is
	// granted for these credentials, but will not log an audit if
	// it fails.
	IsAllowedInternal(permission string) (bool, error)
}

var _ Creds = (*cbauthimpl.CredsImpl)(nil)

type authImpl struct {
	svc *cbauthimpl.Svc
}

// DBStaleError is kind of error that signals that cbauth internal
// state is not synchronized with ns_server yet or anymore.
type DBStaleError struct {
	Err error
}

func (e *DBStaleError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("CBAuth database is stale: last reason: %s", e.Err)
	}
	return "CBAuth database is stale. Was never updated yet."
}

// ErrNoAuth is an error that is returned when the user credentials
// are not recognized
var ErrNoAuth = cbauthimpl.ErrNoAuth

// ErrNoUuid is an error that is returned when the uuid for user is
// empty
var ErrNoUuid = cbauthimpl.ErrNoUuid

// UnknownHostPortError is returned from GetMemcachedServiceAuth and
// GetHTTPServiceAuth calls for unknown host:port arguments.
type UnknownHostPortError string

func (s UnknownHostPortError) Error() string {
	return fmt.Sprintf("Unable to find given hostport in cbauth database: `%s'", string(s))
}

func (a *authImpl) AuthWebCreds(req *http.Request) (creds Creds, err error) {
	return a.AuthWebCredsCore(req.Header, req.TLS)
}

func (a *authImpl) AuthWebCredsGeneric(req httpreq.HttpRequest) (creds Creds,
	err error) {
	var hdr httpreq.HttpHeader = req
	return a.AuthWebCredsCore(hdr, req.GetTLS())
}

func (a *authImpl) AuthWebCredsCore(Hdr httpreq.HttpHeader,
	TLSState *tls.ConnectionState) (creds Creds, err error) {
	if cbauthimpl.IsAuthTokenPresent(Hdr) {
		return cbauthimpl.VerifyOnServer(a.svc, Hdr)
	}

	rv, err := cbauthimpl.MaybeGetCredsFromCert(a.svc, TLSState)
	if err != nil {
		return nil, err
	} else if rv != nil {
		return rv, nil
	}

	user, pwd, err := ExtractCredsGeneric(Hdr)
	if err != nil {
		return nil, err
	}
	if user == "" && pwd == "" {
		return nil, fmt.Errorf("no web credentials found in request")
	}
	onBehalfUser, onBehalfDomain, err := ExtractOnBehalfIdentityGeneric(Hdr)
	if err != nil {
		return nil, err
	}

	if onBehalfUser == "" && onBehalfDomain == "" {
		return cbauthimpl.VerifyPassword(a.svc, user, pwd)
	}
	return cbauthimpl.VerifyOnBehalf(a.svc, user, pwd,
		onBehalfUser, onBehalfDomain)
}

func (a *authImpl) Auth(user, pwd string) (creds Creds, err error) {
	return cbauthimpl.VerifyPassword(a.svc, user, pwd)
}

func (a *authImpl) GetMemcachedServiceAuth(hostport string) (user, pwd string, err error) {
	host, port, err := SplitHostPort(hostport)
	if err != nil {
		return "", "", err
	}
	user, _, pwd, err = cbauthimpl.GetCreds(a.svc, host, port)
	if err == nil && user == "" && pwd == "" {
		return "", "", UnknownHostPortError(hostport)
	}
	return
}

func (a *authImpl) GetHTTPServiceAuth(hostport string) (user, pwd string, err error) {
	host, port, err := SplitHostPort(hostport)
	if err != nil {
		return "", "", err
	}
	_, user, pwd, err = cbauthimpl.GetCreds(a.svc, host, port)
	if err == nil && user == "" && pwd == "" {
		return "", "", UnknownHostPortError(hostport)
	}
	return
}

func (a *authImpl) RegisterTLSRefreshCallback(callback TLSRefreshCallback) error {
	return cbauthimpl.RegisterTLSRefreshCallback(a.svc, cbauthimpl.TLSRefreshCallback(callback))
}

func (a *authImpl) RegisterConfigRefreshCallback(cb ConfigRefreshCallback) error {
	return cbauthimpl.RegisterConfigRefreshCallback(
		a.svc,
		cbauthimpl.ConfigRefreshCallback(cb))
}

func (a *authImpl) GetClientCertAuthType() (tls.ClientAuthType, error) {
	return cbauthimpl.GetClientCertAuthType(a.svc)
}

func (a *authImpl) GetClusterEncryptionConfig() (ClusterEncryptionConfig, error) {
	cfg, err := cbauthimpl.GetClusterEncryptionConfig(a.svc)
	return ClusterEncryptionConfig(cfg), err
}

func (a *authImpl) GetTLSConfig() (TLSConfig, error) {
	cfg, err := cbauthimpl.GetTLSConfig(a.svc)
	return TLSConfig(cfg), err
}

func (a *authImpl) GetUserUuid(user, domain string) (string, error) {
	uuid, err := cbauthimpl.GetUserUuid(a.svc, user, domain)
	return uuid, err
}

func (a *authImpl) GetNodeUuid() (string, error) {
	return cbauthimpl.GetNodeUuid(a.svc)
}

func (a *authImpl) SetExpectedClusterUuid(clusterUUID string) error {
	return cbauthimpl.SetExpectedClusterUuid(a.svc, clusterUUID)
}

func (a *authImpl) GetClusterUuid() (string, error) {
	return cbauthimpl.GetClusterUuid(a.svc)
}

func (a *authImpl) GetUserBuckets(user, domain string) ([]string, error) {
	bucketsAndPerms, err := cbauthimpl.GetUserBuckets(a.svc, user, domain)
	return bucketsAndPerms, err
}

func (a *authImpl) GetGuardrailStatuses() (GuardrailStatuses, error) {
	cfg, err := cbauthimpl.GetGuardrailStatuses(a.svc)
	return GuardrailStatuses(cfg), err
}

var _ Authenticator = (*authImpl)(nil)
