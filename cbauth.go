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
	"encoding/json"
	"fmt"
	"github.com/couchbase/cbauth/cache"
	"io/ioutil"
	"net/http"
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
	// IsAdmin method returns true iff this creds represent valid
	// admin account.
	IsAdmin() (bool, error)
	// IsAdmin method returns true iff this creds represent valid
	// read only admin account.
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

type credsDB interface {
	VerifyCreds(req *http.Request) (user, role string, buckets map[string]bool, err error)
}

type simpleCreds struct {
	user    string
	role    string
	buckets map[string]bool
}

func (c *simpleCreds) Name() string {
	return c.user
}

func (c *simpleCreds) IsAdmin() (bool, error) {
	return c.role == "admin", nil
}

func (c *simpleCreds) IsROAdmin() (bool, error) {
	return c.role == "admin" || c.role == "ro_admin", nil
}

func (c *simpleCreds) CanAccessBucket(bucket string) (bool, error) {
	return c.role == "admin" || (c.role == "bucket" && c.user == bucket) ||
		(c.role == "anonymous" && c.buckets[bucket]), nil
}

func (c *simpleCreds) CanReadBucket(bucket string) (bool, error) {
	return c.CanAccessBucket(bucket)
}

func (c *simpleCreds) CanDDLBucket(bucket string) (bool, error) {
	return c.CanAccessBucket(bucket)
}

type httpAuthenticator struct {
	client  *http.Client
	authURL string
	cache   *cache.AuthCache
}

type credsResponse struct {
	Role string
	User string
}

func copyHeader(reqFrom, reqTo *http.Request, name string) {
	if val := reqFrom.Header.Get(name); val != "" {
		reqTo.Header.Add(name, val)
	}
}

func (db *httpAuthenticator) VerifyCreds(req *http.Request) (user, role string, buckets map[string]bool, err error) {
	user, role, buckets, err = db.cache.VerifyCreds(req)
	if err == cache.ErrAuthNotSupportedByCache {
		user, role, err = db.verifyToken(req)
		return
	}
	if err == cache.Err401 {
		return "", "", nil, nil
	}
	return
}

func (db *httpAuthenticator) verifyToken(reqToAuth *http.Request) (user, role string, err error) {
	req, err := http.NewRequest("POST", db.authURL, nil)
	if err != nil {
		return
	}
	copyHeader(reqToAuth, req, "ns_server-ui")
	copyHeader(reqToAuth, req, "Cookie")

	client := db.client
	hresp, err := client.Do(req)
	if err != nil {
		return
	}
	defer hresp.Body.Close()
	if hresp.StatusCode == 401 {
		return "", "", nil
	} else if hresp.StatusCode != 200 {
		err = fmt.Errorf("Expecting 200 or 401 from ns_server auth endpoint. Got: %s", hresp.Status)
		return
	}
	body, err := ioutil.ReadAll(hresp.Body)
	if err != nil {
		return
	}

	resp := credsResponse{}
	err = json.Unmarshal(body, &resp)
	if err != nil {
		return
	}
	return resp.User, resp.Role, nil
}

func (db *httpAuthenticator) Auth(user, pwd string) (Creds, error) {
	req, err := http.NewRequest("GET", "http://host/", nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(user, pwd)
	return AuthWebCreds(req)
}

func (db *httpAuthenticator) AuthWebCreds(req *http.Request) (creds Creds, err error) {
	user, role, buckets, err := db.VerifyCreds(req)
	if err != nil {
		return nil, err
	}

	return &simpleCreds{
		user:    user,
		role:    role,
		buckets: buckets,
	}, nil
}

func (db *httpAuthenticator) GetHTTPServiceAuth(hostport string) (user, pwd string, err error) {
	return db.cache.GetHTTPServiceAuth(hostport)
}

func (db *httpAuthenticator) GetMemcachedServiceAuth(hostport string) (user, pwd string, err error) {
	return db.cache.GetMemcachedServiceAuth(hostport)
}

// NewDefaultAuthenticator constructs default Authenticator
// implementation that speaks to given (presumably ns_server) endpoint
// using given auth and http transport. This is mainly intended for
// tests.
func NewDefaultAuthenticator(authURL string, rt http.RoundTripper) Authenticator {
	return newHTTPAuthenticator(authURL, rt, true)
}

func newHTTPAuthenticator(authURL string, rt http.RoundTripper, runRevRPC bool) *httpAuthenticator {
	if rt == nil {
		rt = http.DefaultTransport
	}
	client := &http.Client{Transport: rt}
	return &httpAuthenticator{
		authURL: authURL,
		client:  client,
		cache:   cache.StartAuthCache(runRevRPC),
	}
}
