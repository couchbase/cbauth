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

// Package cbauth provides auth{N,Z} for couchbase server services.
package cbauth

import (
	"fmt"
	"net/http"

	"github.com/couchbase/cbauth/cbauthimpl"
)

// TODO: consider API that would allow us to do digest auth behind the
// scene

// TODO: for GetHTTPServiceAuth consider something more generic such
// as GetHTTPAuthHeader. Or even maybe RoundTrip. So that we can
// handle digest auth

// Authenticator is main cbauth interface. It supports both incoming
// and outgoing auth.
type Authenticator interface {
	// AuthWebCreds method extracts credentials from given http request.
	AuthWebCreds(req *http.Request) (creds Creds, err error)
	// Auth method constructs credentials from given user and password pair.
	Auth(user, pwd string) (creds Creds, err error)
	// GetHTTPServiceAuth returns user/password creds giving
	// "admin" access to given http service inside couchbase cluster.
	GetHTTPServiceAuth(hostport string) (user, pwd string, err error)
	// GetMemcachedServiceAuth returns user/password creds given
	// "admin" access to given memcached service.
	GetMemcachedServiceAuth(hostport string) (user, pwd string, err error)
}

// TODO: get rid of unnecessary error returns

// Creds type represents credentials and answers queries on this creds
// authorized actions. Note: it'll become (possibly much) wider API in
// future, but it's main purpose right now is to get us started.
type Creds interface {
	// Name method returns user name (e.g. for auditing)
	Name() string
	// Source method returns user source (for auditing)
	Source() string
	// IsAllowed method returns true if the permission is granted
	// for these credentials
	IsAllowed(permission string) (bool, error)
	// IsAdmin method returns true iff this creds represent valid
	// admin account.
	IsAdmin() (bool, error)
	// CanReadAnyMetadata method returns true iff this creds has
	// permission to read any metadata (i.e. admin or ro-admin).
	CanReadAnyMetadata() bool
	// IsROAdmin is confusing alias for CanReadAnyMetadata. Don't
	// use!
	IsROAdmin() (bool, error)
	// CanAccessBucket method returns true iff this creds
	// represent valid account that can read/write/query docs in given
	// bucket.
	CanAccessBucket(bucket string) (bool, error)
	// CanReadBucket method returns true iff this creds represent
	// valid account that can read (but not necessarily write)
	// docs in given bucket.
	CanReadBucket(bucket string) (bool, error)
	// CanDDLBucket method returns true iff this creds represent
	// valid account that can DDL in given bucket. Note that at
	// this time it delegates to CanAccessBucket in only
	// implementation.
	CanDDLBucket(bucket string) (bool, error)
}

var _ Creds = (*cbauthimpl.CredsImpl)(nil)

type naCreds struct{}

func (na naCreds) Name() string                                { return "" }
func (na naCreds) Source() string                              { return "" }
func (na naCreds) IsAllowed(permission string) (bool, error)   { return false, nil }
func (na naCreds) IsAdmin() (bool, error)                      { return false, nil }
func (na naCreds) IsROAdmin() (bool, error)                    { return false, nil }
func (na naCreds) CanReadAnyMetadata() bool                    { return false }
func (na naCreds) CanAccessBucket(bucket string) (bool, error) { return false, nil }
func (na naCreds) CanReadBucket(bucket string) (bool, error)   { return false, nil }
func (na naCreds) CanDDLBucket(bucket string) (bool, error)    { return false, nil }

// NoAccessCreds is Creds instance that has no access at
// all. Authenticator returns this Creds instance for incoming auth
// that was not recognized at all as valid user.
var NoAccessCreds Creds = naCreds{}

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

// UnknownHostPortError is returned from GetMemcachedServiceAuth and
// GetHTTPServiceAuth calls for unknown host:port arguments.
type UnknownHostPortError string

func (s UnknownHostPortError) Error() string {
	return fmt.Sprintf("Unable to find given hostport in cbauth database: `%s'", string(s))
}

func doOnServer(s *cbauthimpl.Svc, hdr http.Header) (Creds, error) {
	rv, err := cbauthimpl.VerifyOnServer(s, hdr)
	if rv == nil && err == nil {
		return NoAccessCreds, nil
	}
	return rv, err
}

func doAuth(a *authImpl, user, pwd string, hdr http.Header) (Creds, error) {
	ci, err := cbauthimpl.VerifyPassword(a.svc, user, pwd)
	if err != nil {
		return nil, err
	}

	if ci != nil {
		return ci, nil
	}

	if user == "" {
		return NoAccessCreds, nil
	}

	ldapEnabled, err := cbauthimpl.IsLDAPEnabled(a.svc)
	if err != nil {
		return nil, err
	}

	if !ldapEnabled {
		return NoAccessCreds, nil
	}

	if hdr == nil {
		req, err := http.NewRequest("GET", "http://host/", nil)
		if err != nil {
			panic("Must not happen: " + err.Error())
		}
		req.SetBasicAuth(user, pwd)
		hdr = req.Header
	}
	return doOnServer(a.svc, hdr)
}

func (a *authImpl) AuthWebCreds(req *http.Request) (creds Creds, err error) {
	if cbauthimpl.IsAuthTokenPresent(req) {
		return doOnServer(a.svc, req.Header)
	}
	user, pwd, err := ExtractCreds(req)
	if err != nil {
		return nil, err
	}
	return doAuth(a, user, pwd, req.Header)
}

func (a *authImpl) Auth(user, pwd string) (creds Creds, err error) {
	return doAuth(a, user, pwd, nil)
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

var _ Authenticator = (*authImpl)(nil)
