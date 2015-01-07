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
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"testing"
)

type testingRoundTripper struct {
	method  string
	url     string
	user    string
	auth    string
	token   string
	role    string
	tripped bool
}

func newTestingRT(method, uri string) *testingRoundTripper {
	return &testingRoundTripper{
		method: method,
		url:    uri,
	}
}

func assertNoError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func (rt *testingRoundTripper) RoundTrip(req *http.Request) (res *http.Response, err error) {
	if rt.tripped {
		log.Fatalf("Already tripped")
	}

	rt.tripped = true

	if req.URL.String() != rt.url {
		log.Fatalf("Bad url: %v != %v", rt.url, req.URL)
	}
	if req.Method != rt.method {
		log.Fatalf("Bad method: %s != %s", rt.method, req.Method)
	}

	statusCode := 200

	if req.Header.Get("ns_server-ui") == "yes" {
		token, err := req.Cookie("ui-auth-q")
		if err != nil || rt.token != token.Value {
			statusCode = 401
		}
	} else {
		if req.Header.Get("Authorization") != rt.auth {
			statusCode = 401
		}
	}

	response := ""
	status := "401 Unauthorized"
	if statusCode == 200 {
		if rt.role == "bucket" {
			response = fmt.Sprintf(`{"role": "%s", "user": "%s", "buckets": ["%s"]}`,
				rt.role, rt.user, rt.user)
		} else {
			response = fmt.Sprintf(`{"role": "%s", "user": "%s"}`, rt.role, rt.user)
		}
		status = "200 OK"
	}

	respBody := ioutil.NopCloser(strings.NewReader(response))

	return &http.Response{
		Status:        status,
		StatusCode:    statusCode,
		Proto:         "HTTP/1.0",
		ProtoMajor:    1,
		ProtoMinor:    0,
		Header:        http.Header{},
		Body:          respBody,
		ContentLength: -1,
		Trailer:       http.Header{},
		Request:       req,
	}, nil
}

func (rt *testingRoundTripper) resetTripped() {
	rt.tripped = false
}

func (rt *testingRoundTripper) assertTripped(expected bool) {
	if rt.tripped != expected {
		log.Fatalf("Tripped is not expected. Have: %v, need: %v", rt.tripped, expected)
	}
}

func (rt *testingRoundTripper) setAuth(user, pwd, role string) {
	req, err := http.NewRequest("GET", "http://host", nil)
	if err != nil {
		log.Fatalf("Error creating request")
	}
	req.SetBasicAuth(user, pwd)
	rt.token = ""
	rt.user = user
	rt.role = role
	rt.auth = req.Header.Get("Authorization")
	return
}

func (rt *testingRoundTripper) setTokenAuth(user, token, role string) {
	rt.token = token
	rt.user = user
	rt.role = role
	rt.auth = ""
}

func mustAccessBucket(c Creds, bucket string) bool {
	rv, err := c.CanAccessBucket(bucket)
	assertNoError(err)
	return rv
}

func mustReadBucket(c Creds, bucket string) bool {
	rv, err := c.CanReadBucket(bucket)
	assertNoError(err)
	return rv
}

func mustIsAdmin(c Creds) bool {
	rv, err := c.IsAdmin()
	assertNoError(err)
	return rv
}

func mustIsROAdmin(c Creds) bool {
	rv, err := c.IsROAdmin()
	assertNoError(err)
	return rv
}

func mustAuthWebCreds(a Authenticator, req *http.Request) Creds {
	c, err := a.AuthWebCreds(req)
	assertNoError(err)
	return c
}

func TestBasicAdmin(t *testing.T) {
	url := "http://127.0.0.1:9000/_auth"

	tr := newTestingRT("POST", url)
	tr.setAuth("Administrator", "asdasd", "admin")
	a := NewDefaultAuthenticator(url, "something", "something", tr)

	req, err := http.NewRequest("GET", "http://q:11234/_queryStatsmaybe", nil)
	assertNoError(err)
	req.SetBasicAuth("Administrator", "asdasd")

	c := mustAuthWebCreds(a, req)

	if !mustIsAdmin(c) {
		t.Errorf("Expect isAdmin to be true")
	}

	if !mustIsROAdmin(c) {
		t.Errorf("Expect isROAdmin to be true")
	}

	if c.Name() != "Administrator" {
		t.Errorf("Expect name to be Administrator")
	}

	accessBucket := mustAccessBucket(c, "asdasdasdasd") && mustAccessBucket(c, "ffee")
	if !accessBucket {
		t.Errorf("Expected to be able to access all buckets")
	}

	tr.resetTripped()
	req.SetBasicAuth("admin", "wrong")

	c = mustAuthWebCreds(a, req)
	tr.assertTripped(true)

	if mustIsAdmin(c) {
		t.Errorf("Expect isAdmin to be false")
	}
}

func TestROAdmin(t *testing.T) {
	url := "http://127.0.0.1:9000/_auth"

	tr := newTestingRT("POST", url)
	tr.setAuth("roadmin", "asdasd", "ro_admin")
	a := NewDefaultAuthenticator(url, "something", "something", tr)

	req, err := http.NewRequest("GET", "http://q:11234/_queryStatsmaybe", nil)
	assertNoError(err)
	req.SetBasicAuth("roadmin", "asdasd")

	c := mustAuthWebCreds(a, req)

	if mustIsAdmin(c) {
		t.Errorf("Expect isAdmin to be false")
	}

	if !mustIsROAdmin(c) {
		t.Errorf("Expect isROAdmin to be true")
	}

	if mustReadBucket(c, "default") || mustReadBucket(c, "asdsad") {
		t.Errorf("Expect all read access to buckets to be forbidden")
	}

	if mustAccessBucket(c, "default") || mustAccessBucket(c, "foorbar") {
		t.Errorf("Expect bucket access to be forbidden")
	}
}

func TestBasicBucket(t *testing.T) {
	url := "http://127.0.0.1:9000/_auth"

	tr := newTestingRT("POST", url)
	tr.setAuth("foo", "asdasd", "bucket")
	a := NewDefaultAuthenticator(url, "something", "something", tr)

	req, err := http.NewRequest("GET", "http://q:11234/foo/_query", nil)
	assertNoError(err)
	req.SetBasicAuth("foo", "asdasd")

	c := mustAuthWebCreds(a, req)

	t.Log("http call is not lazy. Should happen at once")
	tr.assertTripped(true)

	t.Log("bucket foo access should be allowed")
	if !mustAccessBucket(c, "foo") {
		t.Errorf("access is expected to be allowed")
	}

	if !mustReadBucket(c, "foo") {
		t.Errorf("read access is expected to be allowed")
	}

	if mustIsAdmin(c) {
		t.Errorf("Expect isAdmin to be false")
	}

	if mustIsROAdmin(c) {
		t.Errorf("Expect isROAdmin to be false")
	}

	if mustAccessBucket(c, "foo1") {
		t.Errorf("access to wrong bucket")
	}

	if mustReadBucket(c, "foo1") {
		t.Errorf("read access to wrong bucket")
	}
}

func TestTokenAdmin(t *testing.T) {
	url := "http://127.0.0.1:9000/_auth"

	tr := newTestingRT("POST", url)
	tr.setTokenAuth("Administrator", "1234567890", "admin")
	a := NewDefaultAuthenticator(url, "something", "something", tr)

	req, err := http.NewRequest("GET", "http://q:11234/_queryStatsmaybe", nil)
	assertNoError(err)
	req.Header.Set("Cookie", "ui-auth-q=1234567890")
	req.Header.Set("ns_server-ui", "yes")

	c := mustAuthWebCreds(a, req)

	if !mustIsAdmin(c) {
		t.Errorf("Expect isAdmin to be true")
	}

	if c.Name() != "Administrator" {
		t.Errorf("Expect name to be Administrator")
	}

	accessBucket := mustAccessBucket(c, "asdasdasdasd") && mustAccessBucket(c, "ffee")
	if !accessBucket {
		t.Errorf("Expected to be able to access all buckets")
	}
}
