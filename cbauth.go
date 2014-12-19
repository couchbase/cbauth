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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
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
	VerifyCreds(user, pwd, bucket string) (allowed, isAdmin bool, isRoAdmin bool, err error)
}

type simpleCreds struct {
	user      string
	pwd       string
	verified  bool
	isAdmin   bool
	isROAdmin bool
	isAllowed bool
	bucket    string
	db        credsDB
}

func verifySimple(c *simpleCreds, bucket string) error {
	ok, isAdmin, isROAdmin, err := c.db.VerifyCreds(c.user, c.pwd, bucket)
	if err != nil {
		return err
	}
	c.verified = true
	c.isAdmin = isAdmin
	c.isROAdmin = isROAdmin
	if ok {
		c.bucket = bucket
	}
	return nil
}

func maybeVerifySimple(c *simpleCreds, bucket string, cont func() bool) (bool, error) {
	if c.verified {
		if c.isAdmin || c.isROAdmin || bucket == "" || c.bucket == bucket {
			return cont(), nil
		}
	}
	err := verifySimple(c, bucket)
	if err != nil {
		return false, err
	}
	return cont(), nil
}

func (c *simpleCreds) Name() string {
	return c.user
}

func (c *simpleCreds) IsAdmin() (bool, error) {
	return maybeVerifySimple(c, "", func() bool {
		return c.isAdmin
	})
}

func (c *simpleCreds) CanAccessBucket(bucket string) (bool, error) {
	if bucket == "" {
		return false, nil
	}
	return maybeVerifySimple(c, bucket, func() bool {
		return c.isAdmin || c.bucket == bucket
	})
}

func (c *simpleCreds) CanReadBucket(bucket string) (bool, error) {
	if bucket == "" {
		return false, nil
	}
	return maybeVerifySimple(c, bucket, func() bool {
		return c.isAdmin || c.bucket == bucket || c.isROAdmin
	})
}

func (c *simpleCreds) CanDDLBucket(bucket string) (bool, error) {
	return c.CanAccessBucket(bucket)
}

type nilCredsDB struct{}

func (c nilCredsDB) VerifyCreds(user, pwd, bucket string) (allowed, isAdmin, isRoAdmin bool, err error) {
	return false, false, false, nil
}

var nilCreds = &simpleCreds{verified: true, db: nilCredsDB{}}

func extractCreds(req *http.Request) (user string, pwd string, err error) {
	auth := req.Header.Get("Authorization")
	basicPrefix := "Basic "
	if !strings.HasPrefix(auth, basicPrefix) {
		if auth != "" {
			err = errors.New("Non-basic auth is not supported")
		}
		return
	}
	decodedAuth, err := base64.StdEncoding.DecodeString(auth[len(basicPrefix):])
	if err != nil {
		return
	}
	idx := bytes.IndexByte(decodedAuth, ':')
	if idx < 0 {
		err = errors.New("Malformed basic auth header")
		return
	}
	user = string(decodedAuth[0:idx])
	pwd = string(decodedAuth[(idx + 1):])
	return
}

type httpAuthenticator struct {
	client     *http.Client
	authURL    string
	authTokenU string
	authTokenP string
}

func (db *httpAuthenticator) doCall(method string, values url.Values, resp interface{}) (err error) {
	values.Set("method", method)
	req, err := http.NewRequest("POST", db.authURL, strings.NewReader(values.Encode()))
	if err != nil {
		return
	}
	req.SetBasicAuth(db.authTokenU, db.authTokenP)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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

	return json.Unmarshal(body, resp)
}

type credsResponse struct {
	IsAdmin   bool
	IsROAdmin bool `json:"isROAdmin"`
	Allowed   bool
}

func (db *httpAuthenticator) VerifyCreds(user, pwd, bucket string) (allowed, isAdmin, isRoAdmin bool, err error) {
	values := url.Values{}
	values.Set("user", user)
	values.Set("pwd", pwd)
	if bucket != "" {
		values.Set("bucket", bucket)
	}
	resp := credsResponse{}
	db.doCall("auth", values, &resp)
	if err != nil {
		return
	}
	allowed = resp.Allowed
	isAdmin = resp.IsAdmin
	isRoAdmin = resp.IsROAdmin
	return
}

func (db *httpAuthenticator) Auth(user, pwd string) (Creds, error) {
	return &simpleCreds{
		user: user,
		pwd:  pwd,
		db:   db,
	}, nil
}

func (db *httpAuthenticator) AuthWebCreds(req *http.Request) (creds Creds, err error) {
	creds = nilCreds
	user, pwd, err := extractCreds(req)
	if err != nil {
		return
	}
	creds = &simpleCreds{
		user: user,
		pwd:  pwd,
		db:   db,
	}
	return
}

type getAuthResponse struct {
	User string
	Pwd  string
}

func doGetAuthCall(db *httpAuthenticator, hostport string, call string) (user, pwd string, err error) {
	values := url.Values{}
	values.Set("hostport", hostport)
	resp := getAuthResponse{}
	err = db.doCall(call, values, &resp)
	if err != nil {
		return
	}
	user = resp.User
	pwd = resp.Pwd
	return
}

func (db *httpAuthenticator) GetHTTPServiceAuth(hostport string) (user, pwd string, err error) {
	return doGetAuthCall(db, hostport, "getHTTPAuth")
}

func (db *httpAuthenticator) GetMemcachedServiceAuth(hostport string) (user, pwd string, err error) {
	return doGetAuthCall(db, hostport, "getMcdAuth")
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
