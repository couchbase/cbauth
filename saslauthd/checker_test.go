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

package saslauthd

import (
	"bytes"
	"io"
	"io/ioutil"
	"net"
	"testing"
)

type fakeConnect struct{ net.Conn }

func (c fakeConnect) Body() (rv io.ReadWriteCloser, err error) {
	return c.Conn, nil
}

func maybeFatal(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func miniAssert(t *testing.T, ok bool) {
	if !ok {
		panic(t)
	}
}

func TestAuthBasic(t *testing.T) {
	s1, s2 := net.Pipe()
	go s2.Write([]byte("\x00\x02OK"))
	bufchan := make(chan []byte)
	go func() {
		b := make([]byte, 1024)
		n, err := s2.Read(b)
		t.Log("readen: ", n, err)
		if err != nil {
			panic(err)
		}
		bufchan <- b[:n]
	}()
	ok, err := AuthWithConnect("a", "b", "cd", "e", fakeConnect{s1}.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expect ok to be true")
	}
	s1.Close()
	buf := <-bufchan
	rest, err := ioutil.ReadAll(s2)
	maybeFatal(t, err)
	// we know that response is sent to us by single Write, which
	// is consumed in buf
	miniAssert(t, len(rest) == 0)

	rd := bytes.NewBuffer(buf)
	user, err := readString(rd)
	maybeFatal(t, err)
	pwd, err := readString(rd)
	maybeFatal(t, err)
	svc, err := readString(rd)
	maybeFatal(t, err)
	realm, err := readString(rd)
	maybeFatal(t, err)
	miniAssert(t, string(user) == "a")
	miniAssert(t, string(pwd) == "b")
	miniAssert(t, string(svc) == "cd")
	miniAssert(t, string(realm) == "e")
}
