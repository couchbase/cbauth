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

// +build linux freebsd netbsd solaris darwin

package saslauthd

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"os"
)

func readString(r io.Reader) ([]byte, error) {
	var size uint16
	err := binary.Read(r, binary.BigEndian, &size)
	if err != nil {
		return nil, err
	}
	b := make([]byte, int(size))
	_, err = io.ReadFull(r, b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func writeString(w io.Writer, s string) error {
	b := make([]byte, 2+len(s))
	binary.BigEndian.PutUint16(b, uint16(len(s)))
	copy(b[2:], s)
	_, err := w.Write(b)
	return err
}

func writeReq(w io.Writer, user, pwd, service, realm string) error {
	blen := 2*4 + len(user) + len(pwd) + len(service) + len(realm)
	buf := bytes.NewBuffer(make([]byte, blen)[:0])
	writeString(buf, user)
	writeString(buf, pwd)
	writeString(buf, service)
	writeString(buf, realm)
	if len(buf.Bytes()) != blen {
		panic("BUG")
	}
	_, err := w.Write(buf.Bytes())
	return err
}

var sockPath = initSockpath()

func initSockpath() string {
	s := os.Getenv("CBAUTH_SOCKPATH")
	if s == "" {
		s = "/var/run/saslauthd/mux"
	}
	return s
}

type ConnectFn func() (io.ReadWriteCloser, error)

func connect() (io.ReadWriteCloser, error) {
	return net.Dial("unix", sockPath)
}

func AuthWithConnect(user, pwd, service, real string, connect ConnectFn) (ok bool, err error) {
	conn, err := connect()
	if err != nil {
		return
	}
	defer conn.Close()
	err = writeReq(conn, user, pwd, service, real)
	if err != nil {
		return
	}
	resp, err := readString(bufio.NewReader(conn))
	ok = (len(resp) >= 2 && string(resp[:2]) == "OK")
	return
}

func Auth(user, pwd, service, real string) (ok bool, err error) {
	return AuthWithConnect(user, pwd, service, real, connect)
}

func Supported() bool {
	return true
}

func Available() bool {
	c, _ := connect()
	if c != nil {
		c.Close()
	}
	return c != nil
}
