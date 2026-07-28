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

// Package metakv2 provides a KV API to ns_server's metakv2 store, which
// keeps its values in chronicle rather than in ns_config.
//
// Leaf operations are covered here, along with the removal of a whole
// directory and the quorum wait a fresh read needs. The store also has
// directory creation and listing, bulk mutations and snapshot reads, none of
// which have a caller in Go yet.
//
// Two things differ from the metakv package:
//
// A key lives in a directory, and a leaf directly under the root is not
// allowed. So the shallowest usable path is of the form /dir/key. The
// enclosing directories are created on demand.
//
// A leaf may be marked sensitive, which keeps its value out of the store's
// own logs.
//
// Sensitivity is fixed when the leaf is created: an update carries it
// forward, and the store refuses a write that explicitly states the opposite
// of what is stored. Recreating the leaf is the only way to change it.
package metakv2

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/couchbase/cbauth"
	"github.com/couchbase/cbauth/utils"
)

// ErrRevMismatch is returned from Set when the revision passed in does not
// match the one currently stored. Re-read the key and try again.
var ErrRevMismatch = errors.New("Rev mismatch")

// ErrKeyExists is returned from Add and AddSensitive when the key is already
// there.
var ErrKeyExists = errors.New("Key exists")

// ErrNotFound is returned from Get when the key does not exist.
var ErrNotFound = errors.New("Not found")

// ErrTimeout is returned from SyncQuorum when a quorum was not reached in
// time.
var ErrTimeout = errors.New("Timeout")

// ErrSensitiveUnsupported is returned from AddSensitive while the cluster is
// not yet fully upgraded. A caller should wait and retry.
var ErrSensitiveUnsupported = errors.New(
	"Sensitive keys are not supported until the cluster is fully upgraded")

// Rev is a revision of a leaf, used as a CAS value to detect races with
// concurrent mutators.
type Rev string

// Entry is what Get returns about a leaf.
type Entry struct {
	Value []byte
	Rev   Rev
}

type store struct {
	url    *url.URL
	client *http.Client
}

const uaMetaKv2Suffix = "metakv2"
const uaMetaKv2Version = ""

var userAgent = utils.MakeUserAgent(uaMetaKv2Suffix, uaMetaKv2Version)

var defaultStore = initDefaultStore()

func initDefaultStore() *store {
	c := *http.DefaultClient
	c.Transport = cbauth.WrapHTTPTransport(http.DefaultTransport, nil)

	authURL := os.Getenv("CBAUTH_REVRPC_URL")
	u, err := url.Parse(authURL)
	if err == nil {
		u.RawQuery = ""
		u.Fragment = ""
		u.Path = "/_metakv2"
		u.User = nil
	}
	return &store{url: u, client: &c}
}

// The store carries values inside JSON, so they are base64 encoded on the
// way in and decoded on the way out. Without that, key material and anything
// else that is not valid UTF-8 could not survive a round trip.
func encodeValue(value []byte) string {
	return base64.StdEncoding.EncodeToString(value)
}

// leaf is the wire shape of a leaf read, Entry is what the package reports.
type leaf struct {
	// encoding/json decodes a base64 string into a []byte
	Value    []byte `json:"value"`
	Revision Rev    `json:"revision"`
}

// mutationReply is what the store answers a write with. The revision is the
// one the committing transaction was given, and every key that transaction
// wrote now has it, a Get of the key would report the same revision.
// It can be passed back to Set as a CAS value.
type mutationReply struct {
	Revision Rev `json:"revision"`
}

// The store explains a refusal in one of two shapes: a single message, or,
// when it is a request parameter that was rejected, one message per
// parameter.
type errorReply struct {
	Message string            `json:"message"`
	Errors  map[string]string `json:"errors"`
}

type storeError struct {
	status string
	reply  errorReply
}

func (e *storeError) Error() string {
	switch {
	case e.reply.Message != "":
		return fmt.Sprintf("ns_server _metakv2 returned %s: %s", e.status,
			e.reply.Message)
	case len(e.reply.Errors) > 0:
		fields := make([]string, 0, len(e.reply.Errors))
		for name, msg := range e.reply.Errors {
			fields = append(fields, fmt.Sprintf("%s: %s", name, msg))
		}
		sort.Strings(fields)
		return fmt.Sprintf("ns_server _metakv2 returned %s: %s", e.status,
			strings.Join(fields, ", "))
	default:
		return fmt.Sprintf("ns_server _metakv2 returned: %s", e.status)
	}
}

// rejected reports whether the store named this request parameter as the
// reason it refused.
func (e *storeError) rejected(param string) bool {
	_, ok := e.reply.Errors[param]
	return ok
}

// segments counts the way the store does. It splits on "/" and discards
// empty segments, so counting separators would let "//key" pass here only
// to be refused as a top level leaf by the store.
func segments(path string) int {
	return len(strings.FieldsFunc(path, func(r rune) bool {
		return r == '/'
	}))
}

// A bad path is reported rather than panicked on, since a caller may well
// build one out of something it read at runtime, such as a bucket UUID.
func validatePath(path string) error {
	if len(path) == 0 || path[0] != '/' {
		return fmt.Errorf("path %q must begin with /", path)
	}
	if strings.HasSuffix(path, "/") {
		return fmt.Errorf("path %q must not end with \"/\"", path)
	}
	if segments(path) < 2 {
		return fmt.Errorf(
			"path %q must name a key inside a directory, as in /dir/key",
			path)
	}
	return nil
}

// A directory is named the same way as a leaf here, without the trailing
// "/" that the store itself uses to tell the two apart, so that every path
// in this package is written the same way. The separator is added when the
// request is built. Unlike a leaf, a directory may sit directly under the
// root, so one segment is enough.
func validateDirPath(path string) error {
	if len(path) == 0 || path[0] != '/' {
		return fmt.Errorf("path %q must begin with /", path)
	}
	if strings.HasSuffix(path, "/") {
		return fmt.Errorf("path %q must not end with \"/\"", path)
	}
	if segments(path) < 1 {
		return fmt.Errorf("path %q must name a directory, as in /dir", path)
	}
	return nil
}

func doCall(s *store, method, path string, query url.Values,
	body []byte) ([]byte, error) {
	u := *s.url
	u.Path += path
	if query != nil {
		u.RawQuery = query.Encode()
	}

	var reader io.Reader
	if body != nil {
		reader = strings.NewReader(string(body))
	}
	req, err := http.NewRequest(method, u.String(), reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)

	r, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	replyBody, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	switch r.StatusCode {
	case http.StatusOK, http.StatusCreated:
		return replyBody, nil
	case http.StatusConflict:
		return nil, ErrRevMismatch
	case http.StatusNotFound:
		return nil, ErrNotFound
	case http.StatusGatewayTimeout:
		// Only the sync quorum endpoint answers this, and only when it did
		// not hear back from a quorum in time.
		return nil, ErrTimeout
	}

	var e errorReply
	if json.Unmarshal(replyBody, &e) != nil {
		e = errorReply{}
	}
	return nil, &storeError{status: r.Status, reply: e}
}

func (s *store) mutate(path string, value []byte, rev Rev, create bool,
	sensitive bool) (Rev, error) {
	if err := validatePath(path); err != nil {
		return "", err
	}

	// The enclosing directories are created along with the key. Without
	// this the caller would have to walk the path itself.
	query := url.Values{"recursive": {"true"}}
	if create {
		query.Set("create", "true")
		// The flag is only meaningful when the leaf is being created, and
		// the store rejects it outright on a cluster that is not fully
		// upgraded, so it is not sent at all unless it is wanted.
		if sensitive {
			query.Set("sensitive", "true")
		}
	} else if rev != "" {
		query.Set("rev", string(rev))
	}

	body, err := doCall(s, "PUT", path, query,
		[]byte(encodeValue(value)))
	if err == ErrRevMismatch && create {
		// The store answers 409 both for a lost CAS and for a create that
		// found the key already there, so the two are told apart here by
		// what was asked of it. A create carries no revision, and reporting
		// a revision mismatch to a caller that never supplied one would
		// invite it to retry something that cannot start succeeding.
		return "", ErrKeyExists
	}
	if sensitive {
		// Only the store knows the cluster's compatibility version, so its
		// refusal is the one authoritative answer about whether the mark can
		// be stored yet. It is matched on the parameter the store named
		// rather than on the wording of the complaint.
		var se *storeError
		if errors.As(err, &se) && se.rejected("sensitive") {
			return "", ErrSensitiveUnsupported
		}
	}
	if err == ErrNotFound {
		// On a write the store reports 404 only for a missing directory on
		// the path, never for the key itself, which a write would create.
		// Directories are created for us above, so this is not expected.
		// It is translated rather than returned as ErrNotFound, which from
		// this package means a Get found no key.
		return "", fmt.Errorf("could not write %s, a directory on the path "+
			"is missing", path)
	}
	if err != nil {
		return "", err
	}

	var m mutationReply
	if err := json.Unmarshal(body, &m); err != nil {
		return "", err
	}
	if m.Revision == "" {
		// Every reply to a leaf write states the revision, including the one
		// for a write that stored what was already there. An empty Rev means
		// "no expectation" to Set, so handing one back would quietly turn
		// the caller's next conditional write into an unconditional one.
		// It is reported instead, even though the value did get written.
		return "", fmt.Errorf("%s was written but ns_server _metakv2 "+
			"reported no revision", path)
	}
	return m.Revision, nil
}

func (s *store) syncQuorum(timeout time.Duration) error {
	// The endpoint waits for the whole store rather than for one key, so
	// there is nothing to name in the request.
	//
	// The range the store accepts is not restated here. Only the store
	// knows what it currently accepts, and a copy of the bounds would go
	// stale silently: the rejection would happen here, so a widened range
	// would show up as this package refusing a timeout the store would
	// have taken, with nothing in any server log to say so.
	var query url.Values
	if timeout != 0 {
		query = url.Values{
			"timeout": {strconv.FormatInt(timeout.Milliseconds(), 10)}}
	}

	_, err := doCall(s, "POST", "/_controller/syncQuorum", query, nil)
	return err
}

func (s *store) get(path string) (*Entry, error) {
	if err := validatePath(path); err != nil {
		return nil, err
	}

	body, err := doCall(s, "GET", path, nil, nil)
	if err != nil {
		return nil, err
	}

	var l leaf
	if err := json.Unmarshal(body, &l); err != nil {
		return nil, err
	}
	if l.Revision == "" {
		return nil, fmt.Errorf("ns_server _metakv2 reported no revision "+
			"for %s", path)
	}
	return &Entry{Value: l.Value, Rev: l.Revision}, nil
}

func (s *store) delete(path string) error {
	if err := validatePath(path); err != nil {
		return err
	}

	_, err := doCall(s, "DELETE", path, nil, nil)
	if err == ErrNotFound {
		return nil
	}
	return err
}

func (s *store) recursiveDelete(path string) error {
	if err := validateDirPath(path); err != nil {
		return err
	}

	// Without this the store refuses to remove a directory that still has
	// anything in it, which is never what this call wants.
	query := url.Values{"recursive": {"true"}}

	_, err := doCall(s, "DELETE", path+"/", query, nil)
	if err == ErrNotFound {
		return nil
	}
	return err
}

// Get returns the given key, or ErrNotFound if it does not exist.
//
// It does not report whether the leaf is sensitive, and Entry has no field
// for it. A caller that names a key already knows what it put there, and a
// flag checked at runtime would be the weaker guard, since it holds only as
// long as the leaf was tagged correctly to begin with. The store does report
// it when listing a directory, where the caller receives keys it did not
// name, and this package has no listing call yet.
func Get(path string) (*Entry, error) {
	return defaultStore.get(path)
}

// Add creates the given key, which must not exist yet, and returns the
// revision it was created at. ErrKeyExists is returned if the key is already
// there. Any missing directories along the path are created.
func Add(path string, value []byte) (Rev, error) {
	return defaultStore.mutate(path, value, "", true, false)
}

// AddSensitive is Add for a value that must not be recorded in the logs.
//
// The cluster has to be fully upgraded to accept a sensitive key, and
// ErrSensitiveUnsupported is returned until it is. Nothing is written in that
// case, and the same call succeeds once the upgrade completes.
func AddSensitive(path string, value []byte) (Rev, error) {
	return defaultStore.mutate(path, value, "", true, true)
}

// Set updates the given key, creating it if it does not exist, and returns
// the revision the key now has. That revision can be passed to a later Set
// to make it conditional, with no Get in between.
//
// A non-empty rev makes this update conditional on the stored revision still
// matching, and ErrRevMismatch is returned if it does not. Writing the value
// that is already stored is not an error, and reports the revision the key
// already had, since nothing was committed.
//
// A key that Set creates is not sensitive. The flag can only be set when a
// key is created and AddSensitive is the only way to create one that is.
//
// A key created by AddSensitive stays sensitive across a Set. There is no
// SetSensitive, since sensitivity cannot be changed after creation. Set never
// states the flag on the wire either: stating it would commit the caller to
// whatever is stored, and the store refuses a mismatch, so a Set that sent
// even sensitive=false would fail against every key created sensitive. That
// is what lets a caller use Set without knowing how the key was created.
func Set(path string, value []byte, rev Rev) (Rev, error) {
	return defaultStore.mutate(path, value, rev, false, false)
}

// Delete removes the given key. Deleting a key that does not exist is not
// an error.
func Delete(path string) error {
	return defaultStore.delete(path)
}

// RecursiveDelete removes the given directory and everything underneath it,
// keys and directories alike, in one transaction. Deleting a directory that
// does not exist is not an error.
//
// The path names the directory the same way a key is named, with no trailing
// "/". Note that a directory may sit directly under the root, so passing a
// one segment path such as "/dir" discards everything the package ever put
// under it.
func RecursiveDelete(path string) error {
	return defaultStore.recursiveDelete(path)
}

// SyncQuorum waits until this node's copy of the store has caught up with
// everything a quorum of nodes has committed. A Get reads this node's copy,
// which can lag behind what another node has written, so a caller that must
// not act on a stale value calls this first. ErrTimeout is returned if no
// quorum was reached in time.
//
// The timeout must be between one second and six minutes, which is the range
// the store accepts. Zero leaves the wait to the store's own default.
func SyncQuorum(timeout time.Duration) error {
	return defaultStore.syncQuorum(timeout)
}
