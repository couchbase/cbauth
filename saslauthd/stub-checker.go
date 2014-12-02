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

// +build !linux,!freebsd,!netbsd,!solaris,!darwin

package saslauthd

import (
	"errors"
	"io"
)

var notSupportedErr = errors.New("saslauthd is not supported on this platform")

type ConnectFn func() (io.ReadWriteCloser, error)

func AuthWithConnect(user, pwd, service, real string, connect ConnectFn) (ok bool, err error) {
	return false, notSupportedErr
}

func Auth(user, pwd, service, real string) (ok bool, err error) {
	return false, notSupportedErr
}

func Supported() bool {
	return false
}

func Available() bool {
	return false
}
