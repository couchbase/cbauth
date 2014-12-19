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
	"github.com/couchbase/gomemcached/client"
	couchbase "github.com/couchbaselabs/go-couchbase"
)

type authHandler struct {
	bucket string
	a      Authenticator
}

var _ couchbase.MultiBucketAuthHandler = (*authHandler)(nil)

func (ah *authHandler) GetCredentials() (string, string, string) {
	return "", "", ah.bucket
}

func (ah *authHandler) ForBucket(bucket string) couchbase.AuthHandler {
	copy := *ah
	copy.bucket = bucket
	return &copy
}

func (ah *authHandler) AuthenticateMemcachedConn(host string, conn *memcached.Client) error {
	return WithAuthenticator(ah.a, func(a Authenticator) error {
		u, p, err := a.GetMemcachedServiceAuth(host)
		if err != nil {
			return err
		}
		_, err = conn.Auth(u, p)
		if err == nil && ah.bucket != "" {
			_, err = conn.SelectBucket(ah.bucket)
		}
		return err
	})
}

// NewAuthHandler returns AuthHandler instance that is using given
// authenticator instance to authenticate memcached connections for
// go-couchbase client. If given authenticator is nil, Default
// authenticator will be used during AuthenticateMemcachedConn calls.
func NewAuthHandler(a Authenticator) couchbase.GenericMcdAuthHandler {
	return &authHandler{a: a}
}
