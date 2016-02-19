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
	"encoding/json"
	"log"
	"net/http"
)

type Response struct {
	writer http.ResponseWriter

	status  int
	body    []byte
	headers map[string]string
}

func NewResponse(rw http.ResponseWriter) *Response {
	return &Response{
		writer:  rw,
		status:  http.StatusOK,
		body:    nil,
		headers: make(map[string]string),
	}
}

func (resp *Response) Status(status int) *Response {
	resp.status = status
	return resp
}

func (resp *Response) Header(name, value string) *Response {
	resp.headers[name] = value
	return resp
}

func (resp *Response) Body(value string) *Response {
	resp.body = []byte(value)
	return resp
}

func (resp *Response) JSON(v interface{}) *Response {
	resp.Header("Content-Type", "application/json")
	json, err := json.Marshal(v)
	if err != nil {
		log.Fatalf("Failed to marshal: %s\n%v", err.Error(), v)
	}

	resp.body = json

	return resp
}

func (resp *Response) Write() error {
	headers := resp.writer.Header()
	for name, value := range resp.headers {
		headers.Set(name, value)
	}

	resp.writer.WriteHeader(resp.status)
	_, err := resp.writer.Write([]byte(resp.body))

	return err
}
