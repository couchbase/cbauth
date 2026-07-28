// @author Couchbase <info@couchbase.com>
// @copyright 2026 Couchbase, Inc.
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

package metakv2

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type entry struct {
	value     []byte
	rev       int
	sensitive bool
}

type mockKV struct {
	l    sync.Mutex
	data map[string]entry
	rev  int
	srv  *httptest.Server

	// set to reject a sensitive creation, standing in for a cluster that
	// is not fully upgraded yet
	refuseSensitive bool

	// set to answer a sync quorum request with a timeout, standing in for a
	// cluster that cannot reach a quorum
	failSyncQuorum bool

	lastQuery url.Values
	lastPath  string
}

func revString(rev int) string {
	return fmt.Sprintf("hist:%d", rev)
}

func newMockKV() *mockKV {
	kv := &mockKV{data: make(map[string]entry)}
	kv.srv = httptest.NewServer(http.HandlerFunc(kv.handle))
	return kv
}

func (kv *mockKV) store() *store {
	return storeAt(kv.srv)
}

// storeAt points a store at a bare test server, for the cases that need a
// reply the mock does not produce.
func storeAt(srv *httptest.Server) *store {
	u, err := url.Parse(srv.URL)
	if err != nil {
		panic(err)
	}
	u.Path = "/_metakv2"
	return &store{url: u, client: srv.Client()}
}

// stored is what the mock holds for a path, which is how a test checks
// something the client deliberately does not report back.
func (kv *mockKV) stored(path string) entry {
	kv.l.Lock()
	defer kv.l.Unlock()
	return kv.data[path]
}

// The three shapes the exported API has. A test says which one it is
// exercising instead of carrying two positional booleans to mutate.
func (s *store) add(path string, value []byte) (Rev, error) {
	return s.mutate(path, value, "", true, false)
}

func (s *store) addSensitive(path string, value []byte) (Rev, error) {
	return s.mutate(path, value, "", true, true)
}

func (s *store) set(path string, value []byte, rev Rev) (Rev, error) {
	return s.mutate(path, value, rev, false, false)
}

func (kv *mockKV) close() {
	kv.srv.Close()
}

func replyJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		panic(err)
	}
}

func (kv *mockKV) handle(w http.ResponseWriter, req *http.Request) {
	path, found := strings.CutPrefix(req.URL.Path, "/_metakv2")
	if !found {
		panic("prefix /_metakv2 is not found")
	}

	kv.l.Lock()
	defer kv.l.Unlock()

	query := req.URL.Query()
	kv.lastQuery = query
	kv.lastPath = path

	switch req.Method {
	case "GET":
		e, exists := kv.data[path]
		if !exists {
			replyJSON(w, 404, map[string]string{"message": "Not Found"})
			return
		}
		reply := map[string]any{
			// The store hands back the bytes it was given, as a JSON
			// string. Using []byte here would make encoding/json base64 it
			// a second time and hide the client's own encoding.
			"value":    string(e.value),
			"revision": revString(e.rev),
		}
		replyJSON(w, 200, reply)
	case "PUT":
		body, err := io.ReadAll(req.Body)
		if err != nil {
			panic(err)
		}
		e, exists := kv.data[path]

		if query.Get("create") == "true" {
			if exists {
				replyJSON(w, 409, map[string]string{"message": "Conflict"})
				return
			}
			sensitive := query.Get("sensitive") == "true"
			if sensitive && kv.refuseSensitive {
				// The store rejects the parameter through its request
				// validator, which names the parameter it objected to
				// instead of answering with a single message.
				replyJSON(w, 400, map[string]any{
					"errors": map[string]string{
						"sensitive": "Sensitive keys are not supported " +
							"until the cluster is fully upgraded"}})
				return
			}
			kv.rev++
			kv.data[path] = entry{value: body, rev: kv.rev,
				sensitive: sensitive}
			replyJSON(w, 201, map[string]string{"message": "Created",
				"revision": revString(kv.rev)})
			return
		}

		if rev := query.Get("rev"); rev != "" {
			if !exists || rev != revString(e.rev) {
				replyJSON(w, 409, map[string]string{"message": "Conflict"})
				return
			}
		}
		// Storing what is already there commits nothing, so the revision
		// does not move and the store reports the one the key already had.
		if exists && bytes.Equal(body, e.value) {
			replyJSON(w, 200, map[string]string{"message": "Not Changed",
				"revision": revString(e.rev)})
			return
		}
		kv.rev++
		// Sensitivity is carried forward, never taken from the request.
		kv.data[path] = entry{value: body, rev: kv.rev,
			sensitive: exists && e.sensitive}
		replyJSON(w, 200, map[string]string{"message": "Updated",
			"revision": revString(kv.rev)})
	case "DELETE":
		// A trailing "/" is how the store tells a directory from a leaf.
		if dir, isDir := strings.CutSuffix(path, "/"); isDir {
			var children []string
			for k := range kv.data {
				if strings.HasPrefix(k, dir+"/") {
					children = append(children, k)
				}
			}
			if len(children) == 0 {
				replyJSON(w, 404, map[string]string{"message": "Not Found"})
				return
			}
			// The store keeps a directory that still holds something,
			// unless it was told to take the contents too.
			if query.Get("recursive") != "true" {
				replyJSON(w, 400, map[string]string{"message": "Not Empty"})
				return
			}
			for _, k := range children {
				delete(kv.data, k)
			}
			kv.rev++
			replyJSON(w, 200, map[string]string{"message": "Deleted"})
			return
		}
		if _, exists := kv.data[path]; !exists {
			replyJSON(w, 404, map[string]string{"message": "Not Found"})
			return
		}
		delete(kv.data, path)
		replyJSON(w, 200, map[string]string{"message": "Deleted"})
	case "POST":
		if path != "/_controller/syncQuorum" {
			panic("unexpected POST to " + path)
		}
		if kv.failSyncQuorum {
			replyJSON(w, 504, map[string]string{"message": "Timeout"})
			return
		}
		// validator:integer(timeout, 1000, 360000, _) in menelaus_metakv2,
		// which is the only place the accepted range is stated.
		if t := query.Get("timeout"); t != "" {
			ms, err := strconv.Atoi(t)
			if err != nil || ms < 1000 || ms > 360000 {
				replyJSON(w, 400, map[string]any{
					"errors": map[string]string{
						"timeout": "The value must be in range from 1000 " +
							"to 360000"}})
				return
			}
		}
		// The store answers an empty object, so there is nothing to read
		// beyond the status.
		replyJSON(w, 200, map[string]any{})
	default:
		panic("unexpected method " + req.Method)
	}
}

// The store keeps what the client sent it, so a value that is not valid
// UTF-8 only survives if the client encodes it. Key material looks like
// this, and it is the reason this package exists.
var binaryValue = []byte{0x00, 0xff, 0xfe, 0x41, 0x00, 0x80}

func TestAddGetRoundTrip(t *testing.T) {
	kv := newMockKV()
	defer kv.close()
	s := kv.store()

	rev, err := s.add("/cbcontbk/key", binaryValue)
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	e, err := s.get("/cbcontbk/key")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !bytes.Equal(e.Value, binaryValue) {
		t.Errorf("value round trip: got %v, want %v", e.Value, binaryValue)
	}
	if e.Rev == "" {
		t.Error("expected a revision")
	}
	// The revision a write reports is the one the key now has, which is what
	// makes it usable as a CAS value without reading the key back.
	if rev != e.Rev {
		t.Errorf("revision reported by the write: got %q, want %q", rev, e.Rev)
	}
	if kv.stored("/cbcontbk/key").sensitive {
		t.Error("key was not created sensitive")
	}
}

func TestAddSensitive(t *testing.T) {
	kv := newMockKV()
	defer kv.close()
	s := kv.store()

	if _, err := s.addSensitive("/cbcontbk/kek", binaryValue); err != nil {
		t.Fatalf("add sensitive: %v", err)
	}

	if !kv.stored("/cbcontbk/kek").sensitive {
		t.Error("expected the key to be stored sensitive")
	}

	// The value round trips, and the read reports nothing about sensitivity.
	e, err := s.get("/cbcontbk/kek")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !bytes.Equal(e.Value, binaryValue) {
		t.Errorf("value round trip: got %v, want %v", e.Value, binaryValue)
	}
}

func TestAddExistingIsKeyExists(t *testing.T) {
	kv := newMockKV()
	defer kv.close()
	s := kv.store()

	if _, err := s.add("/cbcontbk/key", []byte("a")); err != nil {
		t.Fatalf("add: %v", err)
	}
	rev, err := s.add("/cbcontbk/key", []byte("b"))
	if err != ErrKeyExists {
		t.Fatalf("expected ErrKeyExists, got %v", err)
	}
	if rev != "" {
		t.Errorf("a refused create reported revision %q", rev)
	}

	// This is what makes backup's add-or-get pattern work.
	e, err := s.get("/cbcontbk/key")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !bytes.Equal(e.Value, []byte("a")) {
		t.Errorf("value: got %s, want a", e.Value)
	}
}

func TestSetRevision(t *testing.T) {
	kv := newMockKV()
	defer kv.close()
	s := kv.store()

	if _, err := s.add("/cbcontbk/key", []byte("a")); err != nil {
		t.Fatalf("add: %v", err)
	}
	e, err := s.get("/cbcontbk/key")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	rev := e.Rev

	if _, err := s.set("/cbcontbk/key", []byte("b"), rev); err != nil {
		t.Fatalf("set with current rev: %v", err)
	}
	// The stored revision has moved on, so the stale one must be refused.
	_, err = s.set("/cbcontbk/key", []byte("c"), rev)
	if err != ErrRevMismatch {
		t.Fatalf("expected ErrRevMismatch, got %v", err)
	}
}

// A caller that keeps writing the same key can chain the revisions it is
// given, which is the point of reporting them: the read that used to sit
// between two conditional writes is not needed.
func TestSetChainsRevisionsWithoutReading(t *testing.T) {
	kv := newMockKV()
	defer kv.close()
	s := kv.store()

	rev, err := s.add("/cbcontbk/key", []byte("a"))
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	for _, value := range []string{"b", "c", "d"} {
		rev, err = s.set("/cbcontbk/key", []byte(value), rev)
		if err != nil {
			t.Fatalf("set %s with the revision the last write gave: %v",
				value, err)
		}
	}

	e, err := s.get("/cbcontbk/key")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if rev != e.Rev {
		t.Errorf("revision after the last write: got %q, want %q", rev, e.Rev)
	}
	if !bytes.Equal(e.Value, []byte("d")) {
		t.Errorf("value: got %s, want d", e.Value)
	}
}

// Storing the value that is already there commits nothing, and the store
// says so with a 200 that carries the revision the key already had. A caller
// chaining revisions would be stranded if that were reported as a failure or
// answered with an empty revision.
func TestSetUnchangedValueReportsCurrentRevision(t *testing.T) {
	kv := newMockKV()
	defer kv.close()
	s := kv.store()

	rev, err := s.add("/cbcontbk/key", []byte("a"))
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	again, err := s.set("/cbcontbk/key", []byte("a"), rev)
	if err != nil {
		t.Fatalf("set of an unchanged value: %v", err)
	}
	if again != rev {
		t.Errorf("revision: got %q, want the unchanged %q", again, rev)
	}
	// And it is still good for a conditional write.
	if _, err := s.set("/cbcontbk/key", []byte("b"), again); err != nil {
		t.Fatalf("set with the reported revision: %v", err)
	}
}

// A write that reports no revision leaves a caller with something that means
// "no expectation" to Set, so it is an error rather than an empty Rev.
func TestMissingRevisionIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, req *http.Request) {
			replyJSON(w, 201, map[string]string{"message": "Created"})
		}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/_metakv2"
	s := &store{url: u, client: srv.Client()}

	rev, err := s.add("/cbcontbk/key", []byte("a"))
	if err == nil {
		t.Fatal("expected an error")
	}
	if rev != "" {
		t.Errorf("expected no revision, got %q", rev)
	}
	if !strings.Contains(err.Error(), "no revision") {
		t.Errorf("error did not say what was missing: %v", err)
	}
}

func TestGetMissingRevisionIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, req *http.Request) {
			replyJSON(w, 200, map[string]string{"value": "YQ=="})
		}))
	defer srv.Close()

	e, err := storeAt(srv).get("/cbcontbk/key")
	if err == nil {
		t.Fatal("expected an error")
	}
	if e != nil {
		t.Errorf("expected no entry, got %v", e)
	}
	if !strings.Contains(err.Error(), "no revision") {
		t.Errorf("error did not say what was missing: %v", err)
	}
}

// An absent key is an error rather than an empty result, so that a caller
// cannot carry on with no value and no sign that anything was missing.
func TestGetMissingIsErrNotFound(t *testing.T) {
	kv := newMockKV()
	defer kv.close()
	s := kv.store()

	e, err := s.get("/cbcontbk/nope")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if e != nil {
		t.Errorf("expected a nil entry, got %+v", e)
	}
}

func TestDelete(t *testing.T) {
	kv := newMockKV()
	defer kv.close()
	s := kv.store()

	if _, err := s.add("/cbcontbk/key", []byte("a")); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := s.delete("/cbcontbk/key"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.get("/cbcontbk/key"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected the key to be gone, got %v", err)
	}
	// Deleting it again is not an error.
	if err := s.delete("/cbcontbk/key"); err != nil {
		t.Errorf("second delete: %v", err)
	}
}

// Discarding a bucket's key material means removing leaves whose names the
// caller never chose, since a DEK is named after an id the encryption code
// handed out. Naming the enclosing directory is the only way to reach them.
func TestRecursiveDeleteRemovesNamesTheCallerDoesNotKnow(t *testing.T) {
	kv := newMockKV()
	defer kv.close()
	s := kv.store()

	doomed := "/cbcontbk/buckets/uuid-1"
	kept := "/cbcontbk/buckets/uuid-2"
	for _, path := range []string{
		doomed + "/keys/kek",
		doomed + "/keys/deks/active",
		doomed + "/keys/deks/6f1a",
		doomed + "/keys/deks/b207",
		kept + "/keys/kek",
	} {
		if _, err := s.add(path, []byte("v")); err != nil {
			t.Fatalf("add %s: %v", path, err)
		}
	}

	if err := s.recursiveDelete(doomed); err != nil {
		t.Fatalf("recursive delete: %v", err)
	}
	if kv.lastQuery.Get("recursive") != "true" {
		t.Error("the store would have refused a directory that is not empty")
	}

	for _, path := range []string{
		doomed + "/keys/kek",
		doomed + "/keys/deks/active",
		doomed + "/keys/deks/6f1a",
		doomed + "/keys/deks/b207",
	} {
		if _, err := s.get(path); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s outlived its bucket, got %v", path, err)
		}
	}
	// Only the named bucket goes.
	if _, err := s.get(kept + "/keys/kek"); err != nil {
		t.Errorf("another bucket lost its key: %v", err)
	}

	// Discarding what is already gone is not an error, so a cleanup that
	// runs twice is harmless.
	if err := s.recursiveDelete(doomed); err != nil {
		t.Errorf("second recursive delete: %v", err)
	}
}

// A refused sensitive creation has to be told apart from every other
// refusal, since a cluster that is not fully upgraded is a state that passes
// on its own and the call is worth retrying, while falling back to a
// plaintext Add would defeat the point of asking.
func TestSensitiveRefusedIsTyped(t *testing.T) {
	kv := newMockKV()
	defer kv.close()
	kv.refuseSensitive = true
	s := kv.store()

	_, err := s.addSensitive("/cbcontbk/kek", binaryValue)
	if !errors.Is(err, ErrSensitiveUnsupported) {
		t.Fatalf("expected ErrSensitiveUnsupported, got %v", err)
	}
}

// Whichever shape the store explains itself in, the explanation has to
// survive, otherwise a refusal is nothing but a status code.
func TestRefusalCarriesTheReason(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply any
		want  string
	}{
		{"per parameter", map[string]any{
			"errors": map[string]string{"rev": "Invalid revision"}},
			"rev: Invalid revision"},
		{"single message", map[string]any{
			"message": "Creating top level leaves is not allowed"},
			"Creating top level leaves is not allowed"},
		{"nothing to report", map[string]any{}, "400 Bad Request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, req *http.Request) {
					replyJSON(w, 400, tc.reply)
				}))
			defer srv.Close()

			s := storeAt(srv)
			_, err := s.add("/cbcontbk/kek", binaryValue)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error did not carry %q: %v", tc.want, err)
			}
			// Only the sensitive parameter maps to the typed error, so an
			// unrelated refusal must not be mistaken for it.
			if errors.Is(err, ErrSensitiveUnsupported) {
				t.Errorf("unrelated refusal reported as unsupported: %v", err)
			}
		})
	}
}

// Directories are created along with the key, and the flag is only sent
// when it is actually wanted.
func TestRequestParameters(t *testing.T) {
	kv := newMockKV()
	defer kv.close()
	s := kv.store()

	_, err := s.addSensitive("/cbcontbk/buckets/uuid/keys/kek", []byte("a"))
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if got := kv.lastQuery.Get("recursive"); got != "true" {
		t.Errorf("recursive: got %q, want true", got)
	}
	if got := kv.lastQuery.Get("sensitive"); got != "true" {
		t.Errorf("sensitive: got %q, want true", got)
	}

	if _, err := s.add("/cbcontbk/plain", []byte("a")); err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, present := kv.lastQuery["sensitive"]; present {
		t.Error("sensitive was sent for a key that does not want it")
	}

	// An update must not state the flag at all, see Set.
	if _, err := s.set("/cbcontbk/plain", []byte("b"), ""); err != nil {
		t.Fatalf("set: %v", err)
	}
	if _, present := kv.lastQuery["sensitive"]; present {
		t.Error("sensitive was sent on an update")
	}
}

func TestPathValidation(t *testing.T) {
	kv := newMockKV()
	defer kv.close()
	s := kv.store()

	// "//key" and "/toplevel" both name a leaf with no directory to live
	// in, which is what the store refuses as a top level leaf.
	for _, path := range []string{"cbcontbk/key", "/cbcontbk/key/",
		"/toplevel", "//key", "/", ""} {
		if _, err := s.get(path); err == nil {
			t.Errorf("expected %q to be rejected", path)
		}
	}

	// A bad path is refused before anything is asked of the store, so that
	// a write cannot half happen on its way to being rejected.
	kv.lastPath = ""
	for _, path := range []string{"/toplevel", "//key"} {
		if _, err := s.add(path, []byte("a")); err == nil {
			t.Errorf("expected %q to be rejected", path)
		}
		if _, err := s.set(path, []byte("a"), ""); err == nil {
			t.Errorf("expected %q to be rejected", path)
		}
		if err := s.delete(path); err == nil {
			t.Errorf("expected %q to be rejected", path)
		}
	}
	if kv.lastPath != "" {
		t.Errorf("a rejected path still reached the store: %q", kv.lastPath)
	}

	// A directory is written without the trailing "/", and unlike a leaf it
	// may sit directly under the root.
	for _, path := range []string{"cbcontbk", "/cbcontbk/", "/", ""} {
		if err := s.recursiveDelete(path); err == nil {
			t.Errorf("expected directory %q to be rejected", path)
		}
	}
	if err := s.recursiveDelete("/toplevel"); err != nil {
		t.Errorf("a directory under the root is allowed, got %v", err)
	}
}

func TestSyncQuorum(t *testing.T) {
	kv := newMockKV()
	defer kv.close()
	s := kv.store()

	if err := s.syncQuorum(0); err != nil {
		t.Fatalf("sync quorum: %v", err)
	}
	if kv.lastPath != "/_controller/syncQuorum" {
		t.Errorf("path: got %q", kv.lastPath)
	}
	// Nothing is asked for when the caller does not state a timeout, so the
	// store applies its own.
	if _, present := kv.lastQuery["timeout"]; present {
		t.Error("a timeout was sent when none was asked for")
	}

	if err := s.syncQuorum(30 * time.Second); err != nil {
		t.Fatalf("sync quorum with a timeout: %v", err)
	}
	// The store reads milliseconds.
	if got := kv.lastQuery.Get("timeout"); got != "30000" {
		t.Errorf("timeout: got %q, want 30000", got)
	}
}

// A timeout outside the range is refused by the store, and its complaint
// names the parameter it rejected.
func TestSyncQuorumTimeoutRange(t *testing.T) {
	kv := newMockKV()
	defer kv.close()
	s := kv.store()

	for _, timeout := range []time.Duration{time.Millisecond, 999 *
		time.Millisecond, -time.Second, time.Hour} {
		err := s.syncQuorum(timeout)
		if err == nil {
			t.Errorf("expected %s to be rejected", timeout)
			continue
		}
		var se *storeError
		if !errors.As(err, &se) || !se.rejected("timeout") {
			t.Errorf("error for %s did not name the timeout: %v", timeout,
				err)
		}
	}

	// Both ends of the range the store accepts are usable.
	for _, timeout := range []time.Duration{time.Second, 6 * time.Minute} {
		if err := s.syncQuorum(timeout); err != nil {
			t.Errorf("%s should be accepted, got %v", timeout, err)
		}
	}
}

// A quorum that was not reached is worth telling apart, since the call can
// simply be retried.
func TestSyncQuorumTimeoutIsErrTimeout(t *testing.T) {
	kv := newMockKV()
	defer kv.close()
	kv.failSyncQuorum = true
	s := kv.store()

	if err := s.syncQuorum(time.Second); !errors.Is(err, ErrTimeout) {
		t.Fatalf("expected ErrTimeout, got %v", err)
	}
}
