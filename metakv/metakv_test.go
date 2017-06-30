package metakv

import (
	"encoding/binary"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"

	log "github.com/couchbase/clog"
)

type entry struct {
	v []byte
	r []byte
}

type mockKV struct {
	l           sync.Mutex
	counter     uint64
	data        map[string]entry
	subscribers map[uint64]chan KVEntry
	srv         *httptest.Server
}

func (kv *mockKV) runMock() func() {
	srv := httptest.NewServer(http.HandlerFunc(kv.Handle))
	if kv.data == nil {
		kv.data = make(map[string]entry)
		kv.subscribers = make(map[uint64]chan KVEntry)
	}
	kv.srv = srv
	return func() {
		srv.Close()
	}
}

func replyJSON(w http.ResponseWriter, value interface{}) {
	json.NewEncoder(w).Encode(value)
}

func (kv *mockKV) broadcast(kve KVEntry) {
	for _, s := range kv.subscribers {
		s <- kve
	}
}

func (kv *mockKV) setLocked(path string, value string) {
	rev := make([]byte, 8)
	binary.LittleEndian.PutUint64(rev, kv.counter)
	kv.counter++
	v := []byte(value)
	e := entry{v, rev}
	kv.data[path] = e

	kv.broadcast(KVEntry{Path: path, Value: v, Rev: rev})
}

func (kv *mockKV) subscribeLocked(ch chan KVEntry) func() {
	id := kv.counter
	kv.counter++
	kv.subscribers[id] = ch
	return func() {
		kv.l.Lock()
		defer kv.l.Unlock()
		delete(kv.subscribers, id)
	}
}

type entriesSlice []KVEntry

func (p entriesSlice) Len() int {
	return len(p)
}
func (p entriesSlice) Less(i, j int) bool {
	return string(p[i].Path) < string(p[j].Path)
}
func (p entriesSlice) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}

func (kv *mockKV) checkRevision(rev, path string) bool {
	if rev == "" {
		return true
	}
	e := kv.data[path]
	return string(e.r) == rev
}

func (kv *mockKV) Handle(w http.ResponseWriter, req *http.Request) {
	path := strings.TrimPrefix(req.URL.Path, "/_metakv")
	if path == req.URL.Path {
		panic("Prefix /_metakv is not found")
	}
	isDir := strings.HasSuffix(path, "/")

	if req.Method == "GET" && isDir {
		kv.handleIterate(w, req)
		return
	}

	kv.l.Lock()
	defer kv.l.Unlock()

	switch req.Method {
	case "GET":
		e, exists := kv.data[path]
		if !exists {
			w.Write([]byte("{}"))
			return
		}
		replyJSON(w, map[string][]byte{"value": e.v, "rev": e.r})
	case "PUT":
		req.ParseForm()

		form := req.PostForm
		create := form.Get("create") != ""
		value := form.Get("value")
		rev := form.Get("rev")

		if !kv.checkRevision(rev, path) {
			w.WriteHeader(409)
			return
		}

		if create {
			if _, exists := kv.data[path]; exists {
				w.WriteHeader(409)
				return
			}
		}
		kv.setLocked(path, value)
	case "DELETE":
		rev := req.URL.Query().Get("rev")

		if !kv.checkRevision(rev, path) {
			w.WriteHeader(409)
			return
		}

		kv.broadcast(KVEntry{path, nil, nil})
		delete(kv.data, path)
	default:
		w.WriteHeader(404)
	}
}

func (kv *mockKV) handleIterate(w http.ResponseWriter, req *http.Request) {
	kv.l.Lock()
	locked := true
	defer func() {
		if locked {
			kv.l.Unlock()
		}
	}()

	continuous := req.URL.Query().Get("feed") == "continuous"
	entries := make([]KVEntry, 0, len(kv.data))
	for k, e := range kv.data {
		entries = append(entries, KVEntry{Path: k, Value: e.v, Rev: e.r})
	}
	sort.Sort(entriesSlice(entries))
	enc := json.NewEncoder(w)
	for _, e := range entries {
		err := enc.Encode(e)
		if err != nil {
			log.Fatal(err)
		}
	}
	if continuous {
		w.(http.Flusher).Flush()

		ch := make(chan KVEntry, 16)
		defer kv.subscribeLocked(ch)()

		kv.l.Unlock()
		locked = false

		log.Print("Waiting for rows")
		closed := w.(http.CloseNotifier).CloseNotify()

		for {
			select {
			case e := <-ch:
				log.Printf("Observed {%s, %s, %s}", e.Path, e.Value, e.Rev)
				err := enc.Encode(e)
				if err != nil {
					log.Printf("Got error in subscribe path: %v", err)
					return
				}
				w.(http.Flusher).Flush()
			case <-closed:
				log.Print("receiver is dead")
				return
			}
		}
	}
}

type myT struct{ *testing.T }

func (t *myT) okStatus(statusCode int, err error) {
	if err != nil {
		t.Fatalf("Got error from http call: %v", err)
	}
	if statusCode != 200 {
		t.Fatalf("Expected code 200. Got: %d", statusCode)
	}
}

func (t *myT) emptyBody(resp *http.Response, err error) {
	defer resp.Body.Close()
	t.okStatus(resp.StatusCode, err)
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Got error trying to read body: %v", err)
	}
	if len(body) != 0 {
		t.Fatalf("Expected empty body. Got: `%s'", string(body))
	}
}

func must(t *testing.T) *myT { return &myT{t} }

func (kv *mockKV) fullPath(path string) string {
	return kv.srv.URL + "/_metakv" + path
}

func (kv *mockKV) doGet(path string, response interface{}) (statusCode int, err error) {
	resp, err := http.Get(kv.fullPath(path))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, json.NewDecoder(resp.Body).Decode(response)
}

func (kv *mockKV) doPut(path, value string) (resp *http.Response, err error) {
	values := url.Values{"value": {"foobar"}}
	body := strings.NewReader(values.Encode())
	req, err := http.NewRequest("PUT", kv.fullPath(path), body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		return nil, err
	}
	client := &http.Client{}
	return client.Do(req)
}

func TestMock(t *testing.T) {
	kv := &mockKV{}
	defer kv.runMock()()

	var m map[string]interface{}
	must(t).okStatus(kv.doGet("/test", &m))
	if len(m) != 0 {
		t.Fatalf("Expected get against empty kv to return {}")
	}

	must(t).emptyBody(kv.doPut("/test", "foobar"))

	var kve kvEntry
	must(t).okStatus(kv.doGet("/test", &kve))
	if string(kve.Value) != "foobar" {
		t.Fatalf("failed to get expected value (foobar). Got: %s", kve.Value)
	}
}

func TestSanity(t *testing.T) {
	kv := &mockKV{}
	defer kv.runMock()()

	url, err := url.Parse(kv.srv.URL + "/_metakv")
	if err != nil {
		panic(err)
	}

	mockStore := &store{
		url:    url,
		client: http.DefaultClient,
	}

	if err := mockStore.add("/_sanity/garbage", []byte("v"), false); err != nil {
		t.Logf("add failed with: %v", err)
	}
	doExecuteBasicSanityTest(t.Log, mockStore)
}
