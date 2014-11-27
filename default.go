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
	"errors"
	"net/http"
	"os"
)

// TODO: consider prettyfing that default thingy.
var Default Authenticator

func init() {
	authURL := os.Getenv("NS_SERVER_CBAUTH_URL")
	authU := os.Getenv("NS_SERVER_CBAUTH_USER")
	authP := os.Getenv("NS_SERVER_CBAUTH_PWD")
	if authURL != "" {
		Default = NewDefaultAuthenticator(authURL, authU, authP, nil)
	}
}

var NotInitializedError = errors.New("cbauth was not initialized")

func WithDefault(body func(a Authenticator) error) error {
	return WithAuthenticator(nil, body)
}

func WithAuthenticator(a Authenticator, body func(a Authenticator) error) error {
	if a == nil {
		a = Default
		if a == nil {
			return NotInitializedError
		}
	}
	return body(a)
}

func AuthWebCreds(req *http.Request) (creds Creds, err error) {
	if Default == nil {
		return nil, NotInitializedError
	}
	return Default.AuthWebCreds(req)
}

func Auth(user, pwd string) (creds Creds, err error) {
	if Default == nil {
		return nil, NotInitializedError
	}
	return Default.Auth(user, pwd)
}

func GetHTTPServiceAuth(hostport string) (user, pwd string, err error) {
	if Default == nil {
		return "", "", NotInitializedError
	}
	return Default.GetHTTPServiceAuth(hostport)
}

func GetMemcachedServiceAuth(hostport string) (user, pwd string, err error) {
	if Default == nil {
		return "", "", NotInitializedError
	}
	return Default.GetMemcachedServiceAuth(hostport)
}
