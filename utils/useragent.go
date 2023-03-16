// @author Couchbase <info@couchbase.com>
// @copyright 2023 Couchbase, Inc.
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

package utils

import (
	"os"
	"path/filepath"
)

var progname = initProgName()

func initProgName() string {
	return filepath.Base(os.Args[0])
}

func MakeUserAgent(suffix string, version string) string {
	ua := progname
	if suffix != "" {
		ua = ua + "-" + suffix
	}
	if version != "" {
		ua = ua + "/" + version
	}
	return ua
}
