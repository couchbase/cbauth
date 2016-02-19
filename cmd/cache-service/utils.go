// @author Couchbase <info@couchbase.com>
// @copyright 2016 Couchbase, Inc.
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
package main

import (
	"encoding/binary"

	"github.com/couchbase/cbauth/service_api"
)

func EncodeRev(rev uint64) service_api.Revision {
	ext := make(service_api.Revision, 8)
	binary.BigEndian.PutUint64(ext, rev)

	return ext
}

func DecodeRev(ext service_api.Revision) uint64 {
	return binary.BigEndian.Uint64(ext)
}
