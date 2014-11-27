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
	"net/http"
)

func SetRequestAuthVia(req *http.Request, a Authenticator) error {
	return WithAuthenticator(a, func(a Authenticator) (err error) {
		user, pwd, err := a.GetHTTPServiceAuth(req.URL.Host)
		if err != nil {
			return
		}
		req.SetBasicAuth(user, pwd)
		return
	})
}

func SetRequestAuth(req *http.Request) error {
	return SetRequestAuthVia(req, nil)
}

func duplicateStringsSlice(in []string) []string {
	return append([]string{}, in...)
}

func dupHeaders(h http.Header) http.Header {
	rv := make(http.Header)
	for k, v := range h {
		rv[k] = duplicateStringsSlice(v)
	}
	return rv
}

func dupRequest(req *http.Request) *http.Request {
	rv := *req
	rv.Header = dupHeaders(req.Header)
	rv.Trailer = dupHeaders(req.Trailer)
	return &rv
}

type cbauthRoundTripper struct {
	slave http.RoundTripper
	a     Authenticator
}

func (rt *cbauthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req = dupRequest(req)
	if err := SetRequestAuthVia(req, rt.a); err != nil {
		return nil, err
	}
	return rt.slave.RoundTrip(req)
}

func WrapHTTPTransport(transport http.RoundTripper, a Authenticator) http.RoundTripper {
	return &cbauthRoundTripper{
		slave: transport,
		a:     a,
	}
}

func SendUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Basic realm=\"Couchbase\"")
	http.Error(w, "need auth", http.StatusUnauthorized)
}
