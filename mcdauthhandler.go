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

	"github.com/couchbase/gomemcached/client"
	couchbase "github.com/couchbase/go-couchbase"
)

// AuthHandler is a type that implements go-couchbase AuthHandler,
// GenericMcdAuthHandler and HTTPAuthHandler interfaces. It integrate
// cbauth into go-couchbase.
type AuthHandler struct {
	Bucket string
	A      Authenticator
}

var _ couchbase.MultiBucketAuthHandler = (*AuthHandler)(nil)
var _ couchbase.HTTPAuthHandler = (*AuthHandler)(nil)

// GetCredentials method returns empty creds (it is not supposed to be
// used in practice).
func (ah *AuthHandler) GetCredentials() (string, string, string) {
	return "", "", ah.Bucket
}

// ForBucket method returns copy of AuthHandler that is configured for
// different bucket.
func (ah *AuthHandler) ForBucket(bucket string) couchbase.AuthHandler {
	copy := *ah
	copy.Bucket = bucket
	return &copy
}

// SetCredsForRequest calls SetRequestAuthVia on given request and
// authhandler's Authenticator.
func (ah *AuthHandler) SetCredsForRequest(req *http.Request) error {
	return SetRequestAuthVia(req, ah.A)
}

// AuthenticateMemcachedConn method grabs creds for given host
// destination and performs auth and select-bucket on given
// memcached.Client. It is called by go-couchbase as part of setting
// up fresh connection in its memcached connections pool.
func (ah *AuthHandler) AuthenticateMemcachedConn(host string, conn *memcached.Client) error {
	return WithAuthenticator(ah.A, func(a Authenticator) error {
		u, p, err := a.GetMemcachedServiceAuth(host)
		if err != nil {
			return err
		}
		_, err = conn.Auth(u, p)
		if err == nil && ah.Bucket != "" {
			_, err = conn.SelectBucket(ah.Bucket)
		}
		return err
	})
}

// NewAuthHandler returns AuthHandler instance that is using given
// authenticator instance to authenticate memcached connections for
// go-couchbase client. If given authenticator is nil, Default
// authenticator will be used during AuthenticateMemcachedConn calls.
func NewAuthHandler(a Authenticator) *AuthHandler {
	return &AuthHandler{A: a}
}
