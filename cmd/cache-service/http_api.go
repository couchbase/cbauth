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
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	. "github.com/couchbase/cbauth/service_api"
)

type HttpAPI struct {
	mgr   *Mgr
	cache *Cache
}

func (h *HttpAPI) DispatchCache(rw http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case "GET", "POST":
		break
	default:
		methodNotAllowed(rw).Write()
		return
	}

	key := strings.TrimPrefix(req.URL.Path, "/cache/")
	if key == "" {
		notFound(rw).Write()
		return
	}

	owner := h.mgr.GetCurrentTokenMap().FindOwner(key)
	if owner != MyNode {
		host := GetNodeHostName(owner)
		redirect(rw, req, host).Write()
		return
	}

	switch req.Method {
	case "GET":
		h.get(rw, key)
	case "POST":
		h.set(rw, req, key)
	default:
		panic("can't happen")
	}
}

func (h *HttpAPI) get(rw http.ResponseWriter, key string) {
	v, err := h.cache.Get(key)
	if err != nil {
		if err == ErrKeyNotFound {
			notFound(rw).Write()
		} else {
			internalError(rw).Body(err.Error()).Write()
		}

		return
	}

	ok(rw).Body(v).Write()
}

func (h *HttpAPI) set(rw http.ResponseWriter, req *http.Request, key string) {
	value, err := ioutil.ReadAll(req.Body)
	if err != nil {
		internalError(rw).Body("Internal server error: " + err.Error()).Write()
		return
	}

	h.cache.Set(key, string(value))
	ok(rw).Write()
}

type ConcreteToken struct {
	Point uint32 `json:"point"`
	Host  string `json:"host"`
}

func (h *HttpAPI) TokenMap(rw http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" {
		methodNotAllowed(rw).Write()
		return
	}

	tokens := h.mgr.GetCurrentTokenMap().Tokens
	resp := []ConcreteToken(nil)

	hostnames := make(map[NodeId]string)
	for _, token := range tokens {
		server := token.Server
		host, ok := hostnames[server]
		if !ok {
			host = GetNodeHostName(server)
			if host == "" {
				msg := fmt.Sprintf("Internal server error: "+
					"no hostname for %s", server)
				internalError(rw).Body(msg).Write()
				return
			}

			hostnames[server] = host
		}

		resp = append(resp, ConcreteToken{token.Point, host})
	}

	ok(rw).Json(resp).Write()
}

func ok(rw http.ResponseWriter) *Response {
	return NewResponse(rw).Status(http.StatusOK)
}

func notFound(rw http.ResponseWriter) *Response {
	return NewResponse(rw).Status(http.StatusNotFound).Body("Not found")
}

func internalError(rw http.ResponseWriter) *Response {
	return NewResponse(rw).Status(http.StatusInternalServerError)
}

func methodNotAllowed(rw http.ResponseWriter) *Response {
	return NewResponse(rw).Body("Method not allowed").Status(http.StatusMethodNotAllowed)
}

func extractKey(path string) string {
	return strings.TrimPrefix(path, "/cache/")
}

func redirect(rw http.ResponseWriter, req *http.Request, host string) *Response {
	url := *req.URL
	url.Scheme = "http"
	url.Host = host

	resp := NewResponse(rw)
	resp.Header("Location", url.String())
	resp.Header("Cache-Control", "must-revalidate")

	return resp.Status(http.StatusFound)
}

func (api *HttpAPI) ListenAndServe() {
	http.HandleFunc("/cache/", api.DispatchCache)
	http.HandleFunc("/tokenMap", api.TokenMap)

	err := http.ListenAndServe(MyHost, nil)
	if err != nil {
		log.Fatal(err)
	}
}
