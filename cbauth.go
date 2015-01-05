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
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
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
	VerifyCreds(req *http.Request) (user, role string, buckets []string, err error)
}

type simpleCreds struct {
	req      *http.Request
	user     string
	role     string
	buckets  map[string]bool
	verified bool
	db       credsDB
}

func verifySimple(c *simpleCreds) error {
	user, role, buckets, err := c.db.VerifyCreds(c.req)
	if err != nil {
		return err
	}
	c.user = user
	c.role = role
	c.buckets = make(map[string]bool)
	for _, b := range buckets {
		c.buckets[b] = true
	}
	c.verified = true
	return nil
}

func maybeVerifySimple(c *simpleCreds, cont func() bool) (bool, error) {
	if c.verified {
		return cont(), nil
	}
	err := verifySimple(c)
	if err != nil {
		return false, err
	}
	return cont(), nil
}

func (c *simpleCreds) Name() string {
	if c.verified {
		return c.user
	}
	err := verifySimple(c)
	if err != nil {
		return "" //temporary drop the error on the floor. this will be gone after we'll start making non-lazy call
	}
	return c.user
}

func (c *simpleCreds) IsAdmin() (bool, error) {
	return maybeVerifySimple(c, func() bool {
		return c.role == "admin"
	})
}

func (c *simpleCreds) IsROAdmin() (bool, error) {
	return maybeVerifySimple(c, func() bool {
		return c.role == "admin" || c.role == "ro_admin"
	})
}

func (c *simpleCreds) CanAccessBucket(bucket string) (bool, error) {
	if bucket == "" {
		return false, nil
	}
	return maybeVerifySimple(c, func() bool {
		return c.role == "admin" || c.buckets[bucket]
	})
}

func (c *simpleCreds) CanReadBucket(bucket string) (bool, error) {
	return c.CanAccessBucket(bucket)
}

func (c *simpleCreds) CanDDLBucket(bucket string) (bool, error) {
	return c.CanAccessBucket(bucket)
}

type httpAuthenticator struct {
	client     *http.Client
	authURL    string
	authTokenU string
	authTokenP string
}

type credsResponse struct {
	Role    string
	User    string
	Buckets []string
}

func copyHeader(reqFrom, reqTo *http.Request, name string) {
	if val := reqFrom.Header.Get(name); val != "" {
		reqTo.Header.Add(name, val)
	}
}

func (db *httpAuthenticator) VerifyCreds(reqToAuth *http.Request) (user, role string, buckets []string, err error) {
	req, err := http.NewRequest("POST", db.authURL, nil)
	if err != nil {
		return
	}
	copyHeader(reqToAuth, req, "ns_server-ui")
	copyHeader(reqToAuth, req, "Authorization")
	copyHeader(reqToAuth, req, "Cookie")

	client := db.client
	hresp, err := client.Do(req)
	if err != nil {
		return
	}
	defer hresp.Body.Close()
	if hresp.StatusCode == 401 {
		return "", "", nil, nil
	} else if hresp.StatusCode != 200 {
		err = errors.New("Expecting 200 or 401 from ns_server auth endpoint")
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
	return resp.User, resp.Role, resp.Buckets, nil
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
	return &simpleCreds{
		req: req,
		db:  db,
	}, nil
}

type getAuthResponse struct {
	User string
	Pwd  string
}

func doGetAuthCall(db *httpAuthenticator, hostport string, call string) (user, pwd string, err error) {
	url := db.authURL + "/" + url.QueryEscape(hostport) + "/" + call
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	req.SetBasicAuth(db.authTokenU, db.authTokenP)
	client := db.client
	hresp, err := client.Do(req)
	if err != nil {
		return
	}
	defer hresp.Body.Close()
	if hresp.StatusCode != 200 {
		err = errors.New("Expecting 200 from ns_server auth endpoint")
		return
	}
	body, err := ioutil.ReadAll(hresp.Body)
	if err != nil {
		return
	}

	resp := getAuthResponse{}
	err = json.Unmarshal(body, &resp)
	if err != nil {
		return
	}
	return resp.User, resp.Pwd, nil
}

func (db *httpAuthenticator) GetHTTPServiceAuth(hostport string) (user, pwd string, err error) {
	return doGetAuthCall(db, hostport, "http")
}

func (db *httpAuthenticator) GetMemcachedServiceAuth(hostport string) (user, pwd string, err error) {
	return doGetAuthCall(db, hostport, "mcd")
}

// NewDefaultAuthenticator constructs default Authenticator
// implementation that speaks to given (presumably ns_server) endpoint
// using given auth and http transport. This is mainly intended for
// tests.
func NewDefaultAuthenticator(authURL, authU, authP string, rt http.RoundTripper) Authenticator {
	if rt == nil {
		rt = http.DefaultTransport
	}
	client := &http.Client{Transport: rt}
	return &httpAuthenticator{
		authURL:    authURL,
		authTokenU: authU,
		authTokenP: authP,
		client:     client,
	}
}
