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

// Package metakv provides simple KV API to some "metadata store". In
// current implementation it is metadata store that keeps values in
// ns_server's ns_config.
//
// Sub-namespace that is under directory "/checkpoints/" is going to
// be implemented specially. It is intended for xdcr checkpoints and
// will not be replicated between nodes in first version of this
// package.
package metakv

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/couchbase/cbauth"
)

// ErrRevMismatch error is returned from Set and Delete when there is
// rev mismatch
var ErrRevMismatch = errors.New("Rev mismatch")

var errNotFound = errors.New("Not found")

// KVEntry struct represents kv entry returned from ListAllChildren and
// used as a parameter in CallbackV2
type KVEntry struct {
	Path      string
	Value     []byte
	Rev       interface{}
	Sensitive bool
}

// Callback type describes functions that receive mutations from
// RunObserveChildren.
type Callback func(path string, value []byte, rev interface{}) error

// CallbackV2 type describes functions that receive mutations from
// RunObserveChildrenV2.
type CallbackV2 func(entry KVEntry) error

// RevCreate is a special revision which when passed to Set will change
// Set to Add.
var RevCreate = &struct{}{}

type store struct {
	url    *url.URL
	client *http.Client
}

var defaultStore = initDefaultStore()

func initDefaultStore() *store {
	c := *http.DefaultClient
	c.Transport = cbauth.WrapHTTPTransport(http.DefaultTransport, nil)

	authURL := os.Getenv("CBAUTH_REVRPC_URL")
	u, err := url.Parse(authURL)
	if err == nil {
		u.RawQuery = ""
		u.Fragment = ""
		u.Path = "/_metakv"
		u.User = nil
	}
	return &store{url: u, client: &c}
}

func doCallInner(s *store, method, path string, values url.Values) (resp *http.Response, err error) {
	var body io.Reader
	if method == "PUT" && values != nil {
		body = strings.NewReader(values.Encode())
	}
	url := *s.url
	url.Path += path
	req, err := http.NewRequest(method, url.String(), body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if method != "PUT" && values != nil {
		req.URL.RawQuery = values.Encode()
	}
	r, err := s.client.Do(req)
	if err != nil {
		return r, err
	}
	if r.StatusCode == http.StatusConflict {
		return r, ErrRevMismatch
	}
	if r.StatusCode == http.StatusNotFound {
		return r, errNotFound
	}
	if r.StatusCode != 200 {
		return r, fmt.Errorf("ns_server _metakv returned: %s", r.Status)
	}
	return r, err
}

func doCall(s *store, method, path string, values url.Values) (body []byte, err error) {
	r, err := doCallInner(s, method, path, values)
	if r != nil {
		defer r.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(r.Body)
}

func doJSONCall(s *store, method, path string, values url.Values, place interface{}) error {
	body, err := doCall(s, method, path, values)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, place)
}

type kvEntry struct {
	Path      string
	Value     []byte
	Rev       []byte
	Sensitive bool
}

type callbackInt func(entry kvEntry) error

func assertValidPathPrefix(path string) {
	if path[0] != '/' {
		panic("path must begin with /")
	}
}

func assertValidPath(path string) {
	assertValidPathPrefix(path)
	if strings.HasSuffix(path, "/") {
		panic("path must not end with \"/\"")
	}
}

func assertValidDirPath(path string) {
	assertValidPathPrefix(path)
	if !strings.HasSuffix(path, "/") {
		panic("dirpath must end with \"/\"")
	}
}

// Get returns matching value and revision for given key. Returns nil
// value, nil rev and nil error when given path doesn't exist.
func (s *store) get(path string) (value []byte, rev interface{}, err error) {
	assertValidPath(path)
	var kve kvEntry
	err = doJSONCall(s, "GET", path, nil, &kve)
	if err == errNotFound {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	rev = nil
	if kve.Rev != nil {
		rev = kve.Rev
	}
	return kve.Value, rev, nil
}

func mutate(s *store, method string, path string, value []byte, rev interface{}, create bool, sensitive bool) error {
	values := url.Values{
		"value": {string(value)},
	}

	if create || rev == RevCreate {
		rev = nil
		values.Set("create", "1")
	}

	if rev != nil {
		revBytes, ok := rev.([]byte)
		if !ok {
			return ErrRevMismatch
		}
		values.Set("rev", string(revBytes))
	}

	if sensitive {
		values.Set("sensitive", "true")
	} else {
		values.Set("sensitive", "false")
	}

	_, err := doCall(s, method, path, values)
	return err
}

// Set updates given key-value pair. If non-nil, rev is a form of CAS
// value used to detect races with concurrent mutators in typical
// read-modify-write cases. Rev is supposed to be same value that is
// returned from get.
func (s *store) set(path string, value []byte, rev interface{}, sensitive bool) error {
	assertValidPath(path)
	return mutate(s, "PUT", path, value, rev, false, sensitive)
}

// Add creates given kv pair. Which must not exist in storage
// yet. ErrRevMismatch is returned if pair with such key exists.
func (s *store) add(path string, value []byte, sensitive bool) error {
	assertValidPath(path)
	return mutate(s, "PUT", path, value, nil, true, sensitive)
}

// Delete deletes given key.
func (s *store) delete(path string, rev interface{}) error {
	assertValidPath(path)
	return mutate(s, "DELETE", path, nil, rev, false, false)
}

// Recursive Delete deletes all keys that are children of given directory path.
func (s *store) recursiveDelete(dirpath string) error {
	assertValidDirPath(dirpath)
	return mutate(s, "DELETE", dirpath, nil, nil, false, false)
}

// IterateChildren invokes given callback on every kv-pair that's
// child of given directory path. Path must end on "/".
func (s *store) iterateChildren(dirpath string, callback callbackInt) error {
	return doRunObserveChildren(s, dirpath, callback, nil)
}

// RunObserveChildren invokes gen callback on every kv-pair that is
// child of given directory path and then on every mutation of
// affected keys. Deletions will be signalled by passing nil to value
// argument of callback. Returns only when cancel channel is closed or
// when children callback returns error. If exit is due to cancel
// channel being closed returned error is nil. Otherwise error is
// non-nil. Path must end on "/".
func (s *store) runObserveChildren(dirpath string, callback callbackInt,
	cancel <-chan struct{}) error {
	if cancel == nil {
		return nil
	}
	return doRunObserveChildren(s, dirpath, callback, cancel)
}

func doRunObserveChildren(s *store, dirpath string, callback callbackInt,
	cancel <-chan struct{}) error {
	assertValidDirPath(dirpath)
	values := url.Values{}
	if cancel != nil {
		values.Set("feed", "continuous")
	}
	r, err := doCallInner(s, "GET", dirpath, values)
	if r != nil {
		defer r.Body.Close()
	}
	if err != nil {
		return err
	}

	errChan := make(chan error, 1)
	kveChan := make(chan kvEntry)

	go func() {
		dec := json.NewDecoder(r.Body)
		var kve kvEntry
		for {
			err := dec.Decode(&kve)
			if err != nil {
				errChan <- err
				close(kveChan)
				return
			}
			kveChan <- kve
		}
	}()

	effCancel := cancel
	if cancel == nil {
		effCancel = make(chan struct{})
	}

readLoop:
	for {
		select {
		case kve, ok := <-kveChan:
			if !ok {
				err = <-errChan
				break readLoop
			}
			err = callback(kve)
			if err != nil {
				return err
			}

		case err = <-errChan:
			break readLoop

		case <-effCancel:
			r.Body.Close()
			// ensure that worker goroutine is done
			for range kveChan {
			}
			return nil
		}
	}

	if cancel == nil && err == io.EOF {
		err = nil
	}
	return err
}

// Get returns matching value and revision for given key. Returns nil
// value, nil rev and nil error when given path doesn't exist.
func Get(path string) (value []byte, rev interface{}, err error) {
	return defaultStore.get(path)
}

// Set updates given key-value pair. If non-nil, rev is a form of CAS
// value used to detect races with concurrent mutators in typical
// read-modify-write cases. Rev is supposed to be same value that is
// returned from get.
func Set(path string, value []byte, rev interface{}) error {
	return defaultStore.set(path, value, rev, false)
}

// SetSensitive is Set for storing sensitive info.
func SetSensitive(path string, value []byte, rev interface{}) error {
	return defaultStore.set(path, value, rev, true)
}

// Add creates given kv pair. Which must not exist in storage
// yet. ErrRevMismatch is returned if pair with such key exists.
func Add(path string, value []byte) error {
	return defaultStore.add(path, value, false)
}

// AddSensitive is Add for storing sensitive info.
func AddSensitive(path string, value []byte) error {
	return defaultStore.add(path, value, true)
}

// Delete deletes given key.
func Delete(path string, rev interface{}) error {
	return defaultStore.delete(path, rev)
}

// RecursiveDelete deletes all keys that are children of given directory path.
func RecursiveDelete(dirpath string) error {
	return defaultStore.recursiveDelete(dirpath)
}

// IterateChildren invokes given callback on every kv-pair that's
// child of given directory path. Path must end on "/".
func IterateChildren(dirpath string, callback Callback) error {
	return defaultStore.iterateChildren(dirpath,
		func(e kvEntry) error {
			return callback(e.Path, e.Value, e.Rev)
		})
}

// RunObserveChildren invokes gen callback on every kv-pair that is
// child of given directory path and then on every mutation of
// affected keys. Deletions will be signalled by passing nil to value
// argument of callback. Returns only when cancel channel is closed or
// when children callback returns error. If exit is due to cancel
// channel being closed returned error is nil. Otherwise error is
// non-nil. Path must end on "/".
func RunObserveChildren(dirpath string, callback Callback,
	cancel <-chan struct{}) error {
	return defaultStore.runObserveChildren(dirpath,
		func(e kvEntry) error {
			return callback(e.Path, e.Value, e.Rev)
		}, cancel)
}

// IterateChildrenV2 invokes given callback on every kv-pair that's
// child of given directory path. Path must end on "/".
func IterateChildrenV2(dirpath string, callback CallbackV2) error {
	return defaultStore.iterateChildren(dirpath,
		func(e kvEntry) error {
			return callback(KVEntry{e.Path, e.Value, e.Rev,
				e.Sensitive})
		})
}

// RunObserveChildrenV2 invokes gen callback on every kv-pair that is
// child of given directory path and then on every mutation of
// affected keys. Deletions will be signalled by passing nil to value
// argument of callback. Returns only when cancel channel is closed or
// when children callback returns error. If exit is due to cancel
// channel being closed returned error is nil. Otherwise error is
// non-nil. Path must end on "/".
func RunObserveChildrenV2(dirpath string, callback CallbackV2,
	cancel <-chan struct{}) error {
	return defaultStore.runObserveChildren(dirpath,
		func(e kvEntry) error {
			return callback(KVEntry{e.Path, e.Value, e.Rev,
				e.Sensitive})
		}, cancel)
}

// ListAllChildren returns all child entries of given "directory" node.
func ListAllChildren(dirpath string) (entries []KVEntry, err error) {
	return defaultStore.listAllChildren(dirpath)
}

// ListAllChildren returns all child entries of given "directory" node.
func (s *store) listAllChildren(dirpath string) (entries []KVEntry, err error) {
	// nil could be used here, but then empty list becomes nil and
	// in my testing code it means json null is returned rather
	// than empty json array.
	entries = make([]KVEntry, 0, 16)
	err = s.iterateChildren(dirpath,
		func(e kvEntry) error {
			entries = append(entries,
				KVEntry{e.Path, e.Value, e.Rev, e.Sensitive})
			return nil
		})
	return
}
