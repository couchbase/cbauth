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
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type testingRoundTripper struct {
	method         string
	url            string
	auth           string
	expectedValues url.Values
	resultJSON     string
	tripped        bool
}

func (rt testingRoundTripper) duplicate() *testingRoundTripper {
	return &rt
}

func (rt *testingRoundTripper) setAuth(user, pwd string) *testingRoundTripper {
	req, err := http.NewRequest("GET", "http://127.0.0.1", nil)
	assertNoError(err)
	req.SetBasicAuth(user, pwd)
	rt.auth = req.Header.Get("Authorization")
	return rt
}

func NewTestingRT(method, uri string) *testingRoundTripper {
	return &testingRoundTripper{
		method:         method,
		url:            uri,
		expectedValues: url.Values{},
	}
}

func stringToReadCloser(s string) io.ReadCloser {
	return ioutil.NopCloser(strings.NewReader(s))
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

	origRequest := req
	req = dupRequest(req)

	if req.URL.String() != rt.url {
		log.Fatalf("Bad url: %v != %v", rt.url, req.URL)
	}
	if req.Method != rt.method {
		log.Fatalf("Bad method: %s != %s", rt.method, req.Method)
	}
	if gotAuth := req.Header.Get("Authorization"); rt.auth != "" && rt.auth != gotAuth {
		log.Fatalf("Bad Authorization: %s != %s", rt.auth, gotAuth)
	}
	err = req.ParseForm()
	assertNoError(err)

	for k, _ := range req.PostForm {
		if _, ok := rt.expectedValues[k]; !ok {
			log.Fatalf("Unexpected POST param: %v", k)
		}
	}

	for k, v := range rt.expectedValues {
		vr, ok := req.PostForm[k]
		if !ok {
			log.Fatalf("Missing expected POST param: %v", k)
		}
		if vr[0] != v[0] {
			log.Fatalf("Mismatch of expected param (%s): %v != %v", k, v[0], vr[0])
		}
	}

	respBody := stringToReadCloser(rt.resultJSON)

	return &http.Response{
		Status:        "200 OK",
		StatusCode:    200,
		Proto:         "HTTP/1.0",
		ProtoMajor:    1,
		ProtoMinor:    0,
		Header:        http.Header{},
		Body:          respBody,
		ContentLength: -1,
		Trailer:       http.Header{},
		Request:       origRequest,
	}, nil
}

func (rt *testingRoundTripper) setExpected(j string) {
	m := map[string]string{}
	err := json.Unmarshal(([]byte)(j), &m)
	if err != nil {
		log.Fatal(err)
	}
	ev := url.Values{}
	rt.expectedValues = ev
	for k, v := range m {
		ev.Set(k, v)
	}
}

func (rt *testingRoundTripper) setResult(j string) {
	rt.resultJSON = j
}

func (rt *testingRoundTripper) resetTripped() {
	rt.tripped = false
}

func (rt *testingRoundTripper) assertTripped(expected bool) {
	if rt.tripped != expected {
		log.Fatalf("Tripped is not expected. Have: %s, need: %s", rt.tripped, expected)
	}
}

func TestExtractCreds(t *testing.T) {
	req, err := http.NewRequest("GET", "http://127.0.0.1/_asdasd", nil)
	assertNoError(err)
	req.SetBasicAuth("u", "p")
	u, p, err := extractCreds(req)
	assertNoError(err)
	if u != "u" || p != "p" {
		t.Errorf("Expected u:p. Got %s:%s", u, p)
	}
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

func mustAuthWebCreds(a Authenticator, req *http.Request) Creds {
	c, err := a.AuthWebCreds(req)
	assertNoError(err)
	return c
}

func TestBasicAdmin(t *testing.T) {
	url := "http://127.0.0.1:9000/_auth"
	tokenU := "@cookie"
	tokenP := "asda2s"

	tr := NewTestingRT("POST", url).setAuth(tokenU, tokenP)
	a := NewDefaultAuthenticator(url, tokenU, tokenP, tr)

	tr.setExpected(`{"method": "auth", "user": "admin", "pwd": "asdasd"}`)
	tr.setResult(`{"allowed": true, "isAdmin": true}`)

	req, err := http.NewRequest("GET", "http://q:11234/_queryStatsmaybe", nil)
	assertNoError(err)
	req.SetBasicAuth("admin", "asdasd")

	c := mustAuthWebCreds(a, req)
	isAdmin := mustIsAdmin(c)

	if !isAdmin {
		t.Errorf("Expect isAdmin to be true")
	}

	accessBucket := mustAccessBucket(c, "asdasdasdasd") && mustAccessBucket(c, "ffee")
	if !accessBucket {
		t.Errorf("Expected to be able to access all buckets")
	}

	tr.resetTripped()
	tr.setExpected(`{"method": "auth", "user": "admin", "pwd": "sdfsdf"}`)
	tr.setResult(`{"allowed": false, "isAdmin": false}`)

	req.SetBasicAuth("admin", "sdfsdf")

	c = mustAuthWebCreds(a, req)

	isAdmin = mustIsAdmin(c)

	tr.assertTripped(true)

	if isAdmin {
		t.Errorf("Expect isAdmin to be false")
	}
}

func TestROAdmin(t *testing.T) {
	url := "http://127.0.0.1:9000/_auth"
	tokenU := "@cookie"
	tokenP := "asda2s"

	tr := NewTestingRT("POST", url).setAuth(tokenU, tokenP)
	a := NewDefaultAuthenticator(url, tokenU, tokenP, tr)

	tr.setExpected(`{"method": "auth", "user": "admin", "pwd": "asdasd"}`)
	tr.setResult(`{"allowed": false, "isAdmin": false, "isROAdmin": true}`)

	req, err := http.NewRequest("GET", "http://q:11234/_queryStatsmaybe", nil)
	assertNoError(err)
	req.SetBasicAuth("admin", "asdasd")

	c := mustAuthWebCreds(a, req)
	isAdmin := mustIsAdmin(c)

	if isAdmin {
		t.Errorf("Expect isAdmin to be false")
	}

	if !mustReadBucket(c, "default") || !mustReadBucket(c, "asdsad") {
		t.Errorf("Expect all read access to buckets to be granted")
	}

	if mustAccessBucket(c, "default") || mustAccessBucket(c, "foorbar") {
		t.Errorf("Expect bucket access to be forbidden")
	}

	t.Log("Lets test with bucket verification happening first")
	tr.resetTripped()
	tr.setExpected(`{"method": "auth", "user": "admin", "pwd": "asdasd", "bucket": "foobar"}`)
	tr.setResult(`{"allowed": false, "isAdmin": false, "isROAdmin": true}`)

	c = mustAuthWebCreds(a, req)
	if !mustReadBucket(c, "foobar") || !mustReadBucket(c, "asdasd") {
		t.Errorf("expect read access to work")
	}
	if mustAccessBucket(c, "foobar") || mustAccessBucket(c, "asdsd") {
		t.Errorf("expect full access to be forbidden")
	}
}

func TestBasicBucket(t *testing.T) {
	url := "http://127.0.0.1:9000/_auth"
	tokenU := "@cookie"
	tokenP := "asda2s"

	tr := NewTestingRT("POST", url).setAuth(tokenU, tokenP)
	a := NewDefaultAuthenticator(url, tokenU, tokenP, tr)

	req, err := http.NewRequest("GET", "http://q:11234/foo/_query", nil)
	assertNoError(err)
	req.SetBasicAuth("foo", "bar")

	tr.setExpected(`{"method": "auth", "user": "foo", "pwd": "bar", "bucket": "foo"}`)
	tr.setResult(`{"allowed": true, "isAdmin": false}`)

	c := mustAuthWebCreds(a, req)

	t.Log("http call is lazy. Should not occur yet")
	tr.assertTripped(false)

	t.Log("bucket foo access should be allowed")
	if !mustAccessBucket(c, "foo") {
		t.Errorf("access is expected to be allowed")
	}

	t.Log("and that needs http call")
	tr.assertTripped(true)

	t.Log("subsequent is admin check should not require http call and should be false")
	if mustIsAdmin(c) {
		t.Errorf("admin is not expected")
	}

	t.Log("bucket access is cached")
	if !mustAccessBucket(c, "foo") {
		t.Errorf("access should be allowed")
	}

	t.Log("now lets try asking is admin first")
	tr.resetTripped()
	tr.setExpected(`{"method": "auth", "user": "foo", "pwd": "bar"}`)
	tr.setResult(`{"allowed": false, "isAdmin": false}`)

	c = mustAuthWebCreds(a, req)
	if mustIsAdmin(c) {
		t.Errorf("admin is not expected")
	}

	tr.assertTripped(true)

	tr.resetTripped()
	tr.setExpected(`{"method": "auth", "user": "foo", "pwd": "bar", "bucket": "foo"}`)
	tr.resultJSON = `{"allowed": true, "isAdmin": false}`

	if !mustAccessBucket(c, "foo") {
		t.Errorf("access should be allowed")
	}

	tr.assertTripped(true)

	if mustIsAdmin(c) {
		t.Errorf("admin is not expected")
	}

	t.Log("we don't cache negative access")
	tr.resetTripped()
	tr.setExpected(`{"method": "auth", "user": "foo", "pwd": "bar", "bucket": "omega"}`)
	tr.resultJSON = `{"allowed": false, "isAdmin": false}`

	if mustAccessBucket(c, "omega") {
		t.Errorf("Omega access is not expected")
	}
	tr.assertTripped(true)

	tr.resetTripped()
	tr.assertTripped(false)

	if mustAccessBucket(c, "omega") {
		t.Errorf("Omega access is not expected")
	}
	tr.assertTripped(true)
}
