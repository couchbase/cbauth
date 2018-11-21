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
	"github.com/couchbase/cbauth/cbauthimpl"
	"net/http"
	"os"
	"strings"
)

// SetRequestAuthVia sets basic auth header in given http request
// according to given authenticator. It will extract target
// hostname/port from request and figure out right service credentials
// for that endpoint. If nil authenticator is passed, Default
// authenticator is used.
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

// SetRequestAuth sets basic auth header in given http request
// according to default authenticator. Simply calls SetRequestAuthVia
// with nil authenticator.
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

// WrapHTTPTransport constructs http transport that automatically does
// SetRequestAuthVia for requests it sends. As usual, if nil
// authenticator is passed, default authenticator is used.
func WrapHTTPTransport(transport http.RoundTripper, a Authenticator) http.RoundTripper {
	return &cbauthRoundTripper{
		slave: transport,
		a:     a,
	}
}

// SendUnauthorized sends 401 Unauthorized response on given response writer.
func SendUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Basic realm=\"Couchbase\"")
	http.Error(w, "Authentication Failure.", http.StatusUnauthorized)
}

// ForbiddenJSON returns json 403 response for given permission
func ForbiddenJSON(permission string) ([]byte, error) {
	jsonStruct := map[string]interface{}{
		"message":     "Forbidden. User needs one of the following permissions",
		"permissions": [...]string{permission},
	}
	return json.Marshal(jsonStruct)
}

// SendForbidden sends 403 Forbidden with json payload that contains list
// of required permissions to response on given response writer.
func SendForbidden(w http.ResponseWriter, permission string) error {
	b, err := ForbiddenJSON(permission)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	w.Write(b)
	return nil
}

type tlsConfig struct {
	MinTLSVersion string
	Ciphers       []string
	CipherOrder   bool
}

func getTLSConfig() tlsConfig {
	res := tlsConfig{}
	v := os.Getenv("CBAUTH_TLS_CONFIG")
	if len(strings.TrimSpace(v)) != 0 {
		if err := json.Unmarshal([]byte(v), &res); err != nil {
			panic(err)
		}
	}

	return res
}

// Function is deprecated. Use cbauth.GetTLSConfig() instead
func CipherSuites() []uint16 {
	config := getTLSConfig()
	return cbauthimpl.CipherSuites(config.Ciphers)
}

// Function is deprecated. Use cbauth.GetTLSConfig() instead
func CipherOrder() bool {
	config := getTLSConfig()
	return config.CipherOrder
}

// Function is deprecated. Use cbauth.GetTLSConfig() instead
func MinTLSVersion() uint16 {
	config := getTLSConfig()

	return cbauthimpl.MinTLSVersion(config.MinTLSVersion)
}
