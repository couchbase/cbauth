// @author Couchbase <info@couchbase.com>
// @copyright 2015 Couchbase, Inc.
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
	"fmt"

	. "github.com/couchbase/cbauth/service_api"
)

var (
	MyNode NodeId
	MyHost string
)

func InitNode(node NodeId, host string) {
	MyNode = node
	MyHost = host

	SetNodeHostName(node, host)
	MaybeCreateInitialTokenMap()
}

func SetNodeHostName(node NodeId, host string) {
	currentHost := GetNodeHostName(node)
	if host != currentHost {
		MetakvSet(hostPath(node), host)
	}
}

func GetNodeHostName(node NodeId) string {
	host := ""
	MetakvGet(hostPath(node), &host)

	return host
}

func hostPath(node NodeId) string {
	return fmt.Sprintf("%snodes/%s/host", ServiceDir, node)
}
