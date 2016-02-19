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
	"flag"
	"log"

	"github.com/couchbase/cbauth/service_api"
)

func main() {
	node := flag.String("node-id", "", "node id")
	host := flag.String("host", "127.0.0.1:1234", "host+port")
	flag.Parse()

	if *node == "" {
		log.Fatalf("need node-id")
	}

	InitNode(service_api.NodeID(*node), *host)
	RegisterManager()
}
