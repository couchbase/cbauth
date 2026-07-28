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

// The rest of the tests run against a mock, which answers what this package
// believes the store answers. That is the wrong witness for the belief
// itself, so this file runs the same operations against a real ns_server and
// lets chronicle be the witness.
//
// It is off unless CBAUTH_METAKV2_LIVE_URL names an endpoint, so CV and an
// ordinary "go test ./..." skip it and stay hermetic:
//
//	CBAUTH_METAKV2_LIVE_URL=http://127.0.0.1:9000 \
//	CBAUTH_METAKV2_LIVE_PASSWORD=asdasd \
//	go test ./metakv2/ -run TestLive -v
//
// The credentials need the metakv2 permission the endpoint is guarded with.
// The full administrator has it, as does a user holding metakv2_access.
// cluster_admin does not.

package metakv2

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"
)

const (
	liveURLEnv      = "CBAUTH_METAKV2_LIVE_URL"
	liveUserEnv     = "CBAUTH_METAKV2_LIVE_USER"
	livePasswordEnv = "CBAUTH_METAKV2_LIVE_PASSWORD"
)

// liveRoot is the directory a live run owns outright. Everything under it is
// removed before the run as well as after, since a run that dies partway
// leaves keys behind that would turn the next Add into ErrKeyExists.
const liveRoot = "/_cbauth_metakv2_live_test"

// A test process has no revrpc connection, so it cannot use the transport
// initDefaultStore installs, which asks cbauth for the node's own service
// credentials. It presents the operator's credentials instead. Everything
// past the Authorization header is the same request the default store makes.
type basicAuthTransport struct {
	user     string
	password string
	base     http.RoundTripper
}

func (t *basicAuthTransport) RoundTrip(req *http.Request) (*http.Response,
	error) {
	r := req.Clone(req.Context())
	r.SetBasicAuth(t.user, t.password)
	return t.base.RoundTrip(r)
}

func liveStore(t *testing.T) *store {
	t.Helper()

	raw := os.Getenv(liveURLEnv)
	if raw == "" {
		t.Skipf("set %s to run against a live ns_server, as in "+
			"%s=http://127.0.0.1:9000", liveURLEnv, liveURLEnv)
	}

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("%s=%q: %v", liveURLEnv, raw, err)
	}
	u.RawQuery = ""
	u.Fragment = ""
	u.User = nil
	u.Path = "/_metakv2"

	user := os.Getenv(liveUserEnv)
	if user == "" {
		user = "Administrator"
	}

	c := *http.DefaultClient
	c.Transport = &basicAuthTransport{
		user:     user,
		password: os.Getenv(livePasswordEnv),
		base:     http.DefaultTransport,
	}
	return &store{url: u, client: &c}
}

// liveScratch hands back a store with an empty liveRoot, and takes the
// directory away again once the test is done with it.
func liveScratch(t *testing.T) *store {
	t.Helper()

	s := liveStore(t)
	if err := s.recursiveDelete(liveRoot); err != nil {
		t.Fatalf("clearing %s: %v", liveRoot, err)
	}
	t.Cleanup(func() {
		if err := s.recursiveDelete(liveRoot); err != nil {
			t.Errorf("clearing %s: %v", liveRoot, err)
		}
	})
	return s
}

// TestLiveLeaf walks a leaf through its whole life against a real store. It
// is one test rather than several, since each step reads what the one before
// it wrote.
func TestLiveLeaf(t *testing.T) {
	s := liveScratch(t)
	key := liveRoot + "/buckets/uuid/keys/kek"

	if _, err := s.get(key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get of a missing key: got %v, want ErrNotFound", err)
	}

	// Nothing on the path exists yet, so this also exercises the recursive
	// directory creation every write asks for.
	rev1, err := s.add(key, []byte("first"))
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if rev1 == "" {
		t.Fatal("add reported no revision")
	}

	e, err := s.get(key)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(e.Value) != "first" {
		t.Errorf("value: got %q, want %q", e.Value, "first")
	}
	if e.Rev != rev1 {
		t.Errorf("rev: got %q, want %q", e.Rev, rev1)
	}

	if _, err := s.add(key, []byte("again")); !errors.Is(err, ErrKeyExists) {
		t.Errorf("add of an existing key: got %v, want ErrKeyExists", err)
	}

	rev2, err := s.set(key, []byte("second"), rev1)
	if err != nil {
		t.Fatalf("conditional set: %v", err)
	}
	if rev2 == rev1 {
		t.Error("a committed write reported the revision it replaced")
	}

	if _, err := s.set(key, []byte("third"), rev1); !errors.Is(
		err, ErrRevMismatch) {
		t.Errorf("set on a stale revision: got %v, want ErrRevMismatch", err)
	}

	// A write of what is already stored commits nothing, and the store
	// reports the revision the key kept rather than a fresh one.
	rev3, err := s.set(key, []byte("second"), rev2)
	if err != nil {
		t.Fatalf("set of an unchanged value: %v", err)
	}
	if rev3 != rev2 {
		t.Errorf("unchanged set: got rev %q, want %q", rev3, rev2)
	}

	rev4, err := s.set(key, []byte("fourth"), "")
	if err != nil {
		t.Fatalf("unconditional set: %v", err)
	}
	if e, err := s.get(key); err != nil {
		t.Fatalf("get: %v", err)
	} else if string(e.Value) != "fourth" || e.Rev != rev4 {
		t.Errorf("after set: got %q at %q, want %q at %q", e.Value, e.Rev,
			"fourth", rev4)
	}

	if err := s.delete(key); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.get(key); !errors.Is(err, ErrNotFound) {
		t.Errorf("get after delete: got %v, want ErrNotFound", err)
	}
	// Deleting what is not there is how a caller makes a key absent without
	// having to look first.
	if err := s.delete(key); err != nil {
		t.Errorf("delete of a missing key: %v", err)
	}
}

// TestLiveValueRoundTrip checks that a value survives the store byte for
// byte, which is the whole reason values are base64 encoded on the wire.
func TestLiveValueRoundTrip(t *testing.T) {
	s := liveScratch(t)

	// Key material is the case this package was added for, so the value
	// that matters is one that is not valid UTF-8.
	value := []byte{0x00, 0xff, 0xfe, 'a', '\n', 0x80, 0x7f}
	key := liveRoot + "/keys/binary"

	if _, err := s.add(key, value); err != nil {
		t.Fatalf("add: %v", err)
	}
	e, err := s.get(key)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(e.Value) != string(value) {
		t.Errorf("value: got %v, want %v", e.Value, value)
	}

	// An empty value is a value, not an absent key.
	empty := liveRoot + "/keys/empty"
	if _, err := s.add(empty, []byte{}); err != nil {
		t.Fatalf("add of an empty value: %v", err)
	}
	if e, err := s.get(empty); err != nil {
		t.Fatalf("get: %v", err)
	} else if len(e.Value) != 0 {
		t.Errorf("empty value came back as %q", e.Value)
	}
}

// TestLiveSensitive checks the one behaviour this package cannot see: the
// store carries sensitivity forward across an update, so a Set that never
// states the flag does not fail against a key created sensitive.
func TestLiveSensitive(t *testing.T) {
	s := liveScratch(t)
	key := liveRoot + "/keys/secret"

	rev, err := s.addSensitive(key, []byte("secret"))
	if errors.Is(err, ErrSensitiveUnsupported) {
		t.Skip("the cluster is not fully upgraded, so a sensitive key " +
			"cannot be stored yet")
	}
	if err != nil {
		t.Fatalf("add sensitive: %v", err)
	}

	e, err := s.get(key)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(e.Value) != "secret" {
		t.Errorf("value: got %q, want %q", e.Value, "secret")
	}

	if _, err := s.set(key, []byte("rotated"), rev); err != nil {
		t.Fatalf("set of a sensitive key: %v", err)
	}
	if e, err := s.get(key); err != nil {
		t.Fatalf("get: %v", err)
	} else if string(e.Value) != "rotated" {
		t.Errorf("value: got %q, want %q", e.Value, "rotated")
	}
}

// TestLiveRecursiveDelete checks that the whole tree goes, including names
// the caller never mentioned, which is what continuous backup needs when a
// bucket is dropped.
func TestLiveRecursiveDelete(t *testing.T) {
	s := liveScratch(t)

	keys := []string{
		liveRoot + "/buckets/one/keys/kek",
		liveRoot + "/buckets/one/keys/dek",
		liveRoot + "/buckets/two/keys/kek",
		liveRoot + "/top",
	}
	for _, key := range keys {
		if _, err := s.add(key, []byte("v")); err != nil {
			t.Fatalf("add %s: %v", key, err)
		}
	}

	if err := s.recursiveDelete(liveRoot + "/buckets/one"); err != nil {
		t.Fatalf("recursive delete: %v", err)
	}
	for _, key := range keys[:2] {
		if _, err := s.get(key); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s survived: got %v, want ErrNotFound", key, err)
		}
	}
	// A sibling directory is left alone.
	if _, err := s.get(keys[2]); err != nil {
		t.Errorf("get %s: %v", keys[2], err)
	}

	if err := s.recursiveDelete(liveRoot); err != nil {
		t.Fatalf("recursive delete: %v", err)
	}
	for _, key := range keys[2:] {
		if _, err := s.get(key); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s survived: got %v, want ErrNotFound", key, err)
		}
	}
	// Removing a directory that is already gone is not an error.
	if err := s.recursiveDelete(liveRoot); err != nil {
		t.Errorf("recursive delete of a missing directory: %v", err)
	}
}

// TestLiveSyncQuorum only checks that the wait is accepted and returns. On a
// single node cluster a quorum is always at hand, so there is nothing here
// about lag, which needs more than one node to observe.
func TestLiveSyncQuorum(t *testing.T) {
	s := liveStore(t)

	if err := s.syncQuorum(0); err != nil {
		t.Errorf("sync quorum with the store's own timeout: %v", err)
	}
	if err := s.syncQuorum(30 * time.Second); err != nil {
		t.Errorf("sync quorum: %v", err)
	}

	// The store states the bounds it accepts, and this package deliberately
	// does not restate them. A refusal is what proves the request reached
	// the store rather than being screened out here.
	if err := s.syncQuorum(time.Millisecond); err == nil {
		t.Error("a timeout below the accepted range was not refused")
	}
}
