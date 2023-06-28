package cbauth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/couchbase/cbauth/cbauthimpl"
	"github.com/couchbase/cbauth/revrpc"
	log "github.com/couchbase/clog"
)

func newAuth(initPeriod time.Duration) *authImpl {
	return &authImpl{cbauthimpl.NewSVC(initPeriod, &DBStaleError{})}
}

func (a *authImpl) setTransport(rt http.RoundTripper) {
	cbauthimpl.SetTransport(a.svc, rt)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func newAuthForTest(body func(freshChan chan struct{}, timeoutBody func())) *authImpl {
	testDur := 555 * time.Hour

	wf := func(period time.Duration, ch chan struct{}, timeoutBody func()) {
		if period != testDur {
			panic(period)
		}
		body(ch, timeoutBody)
	}

	return &authImpl{cbauthimpl.NewSVCForTest(testDur, &DBStaleError{}, wf)}
}

func acc(ok bool, err error) bool {
	must(err)
	return ok
}

func newCache(a *authImpl) *cbauthimpl.Cache {
	url := "http://127.0.0.1:9000"
	return &cbauthimpl.Cache{
		AuthCheckURL:       url + "/_auth",
		PermissionCheckURL: url + "/_permissions",
		UserBucketsURL:     url + "/_getUserBuckets",
		UuidCheckURL:       url + "/_getUserUuid",
	}
}

type testingUser struct {
	user     string
	domain   string
	password string
}

// GetUserUuid and GetUserBuckets return a result for {user, domain}
type ReqKey struct {
	user   string
	domain string
}

// IsAllowed returns a result for {user, domain, permission}
type ReqKeyPerm struct {
	user       string
	domain     string
	permission string
}

// {req}Map stores expected results for GetUserUuid/GetUserBuckets/IsAllowed
// {req}Hit tracks whether the result should be served from the cache
type GetReqTestInfo struct {
	uuidMap     map[ReqKey]string
	bucketsMap  map[ReqKey][]string
	permMap     map[ReqKeyPerm]bool
	uuidHit     map[ReqKey]bool
	bucketsHit  map[ReqKey]bool
	permHit     map[ReqKeyPerm]bool
	users       []string
	domains     []string
	permissions []string
	numCombos   int
}

type testingRoundTripper struct {
	t                   *testing.T
	info                *GetReqTestInfo
	baseURL             string
	users               []testingUser
	tripped             bool
	disableSerialChecks bool
}

func newTestingRT(t *testing.T) *testingRoundTripper {
	return &testingRoundTripper{
		t:       t,
		baseURL: "http://127.0.0.1:9000",
	}
}

func (rt *testingRoundTripper) RoundTrip(req *http.Request) (res *http.Response, err error) {
	path := strings.TrimPrefix(req.URL.String(), rt.baseURL)

	if req.URL.String() == path {
		log.Fatalf("Bad url: %v", req.URL)
	}

	switch {
	case req.Method == "POST" && path == "/_auth":
		return rt.authRoundTrip(req)
	case req.Method == "GET" && strings.HasPrefix(path, "/_permissions"):
		return rt.permissionsRoundTrip(req)
	case req.Method == "GET" && strings.HasPrefix(path, "/_getUserUuid"):
		return rt.uuidRoundTrip(req)
	case req.Method == "GET" && strings.HasPrefix(path, "/_getUserBuckets"):
		return rt.bucketsRoundTrip(req)
	}

	log.Fatalf("Unrecognized call, method: %s, path: %s", req.Method, path)
	return
}

func respond(req *http.Request, statusCode int, response string) *http.Response {
	respBody := ioutil.NopCloser(strings.NewReader(response))

	status := "None"
	switch statusCode {
	case 401:
		status = "401 Unauthorized"
	case 200:
		status = "200 OK"
	}

	return &http.Response{
		Status:        status,
		StatusCode:    statusCode,
		Proto:         "HTTP/1.0",
		ProtoMajor:    1,
		ProtoMinor:    0,
		Header:        http.Header{},
		Body:          respBody,
		ContentLength: -1,
		Trailer:       http.Header{},
		Request:       req,
	}
}

func (rt *testingRoundTripper) permissionsRoundTrip(req *http.Request) (res *http.Response, err error) {
	params := req.URL.Query()
	permission := params["permission"]
	user := params["user"]
	domain := params["domain"]

	if permission == nil || user == nil || domain == nil {
		log.Fatalf("Missing parameters in request: %s", req.URL.String())
	}

	rt.setTripped()
	statusCode := 401

	if rt.info == nil {
		// for simplicity let's grant the permission that matches the username
		if permission[0] == user[0] {
			statusCode = 200
		}

		if permission[0] == "cluster.admin.security.admin!impersonate" &&
			domain[0] == "admin" {
			statusCode = 200
		}
	} else {
		// TestGetProcessRequest compares results with those in rt.info
		key := ReqKeyPerm{
			user:       user[0],
			domain:     domain[0],
			permission: permission[0],
		}

		if !rt.disableSerialChecks && rt.info.permHit[key] {
			log.Fatalf("Unexpected IsAllowed cache miss: %s %s %s",
				key.user, key.domain, key.permission)
		}
		allowed := rt.info.permMap[key]
		if allowed {
			statusCode = 200
		}
		if !rt.disableSerialChecks && key.domain != "external" {
			rt.info.permHit[key] = true
		}
	}
	return respond(req, statusCode, ""), nil
}

func (rt *testingRoundTripper) uuidRoundTrip(req *http.Request) (res *http.Response, err error) {
	params := req.URL.Query()
	user := params["user"]
	domain := params["domain"]

	if user == nil || domain == nil {
		log.Fatalf("Missing parameters in request: %s", req.URL.String())
	}

	if domain[0] != "local" {
		log.Fatalf("Unexpected domain: %s", domain[0])
	}

	rt.setTripped()

	key := ReqKey{
		user:   user[0],
		domain: domain[0],
	}

	if !rt.disableSerialChecks && rt.info.uuidHit[key] {
		log.Fatalf("Unexpected GetUserUuid cache miss: %s %s",
			key.user, key.domain)
	}

	uuid := rt.info.uuidMap[key]
	if !rt.disableSerialChecks {
		rt.info.uuidHit[key] = true
	}

	resp := make(map[string]string)
	resp["user"] = key.user
	resp["domain"] = key.domain
	resp["uuid"] = uuid
	jsonResp, err := json.Marshal(resp)
	if err != nil {
		log.Fatalf("Error happened in JSON marshal. Err: %s", err)
	}

	return respond(req, 200, string(jsonResp)), nil
}

func (rt *testingRoundTripper) bucketsRoundTrip(req *http.Request) (res *http.Response, err error) {
	params := req.URL.Query()
	user := params["user"]
	domain := params["domain"]

	if user == nil || domain == nil {
		log.Fatalf("Missing parameters in request: %s", req.URL.String())
	}

	rt.setTripped()

	key := ReqKey{
		user:   user[0],
		domain: domain[0],
	}

	if !rt.disableSerialChecks && rt.info.bucketsHit[key] {
		log.Fatalf("Unexpected GetUserBuckets cache miss: %s %s",
			key.user, key.domain)
	}

	buckets := rt.info.bucketsMap[key]
	if !rt.disableSerialChecks {
		rt.info.bucketsHit[key] = true
	}

	jsonResp, err := json.Marshal(buckets)
	if err != nil {
		log.Fatalf("Error happened in JSON marshal. Err: %s", err)
	}

	return respond(req, 200, string(jsonResp)), nil
}

func (rt *testingRoundTripper) authRoundTrip(req *http.Request) (res *http.Response, err error) {
	rt.assertTripped(rt.t, false)
	rt.setTripped()

	var foundUser *testingUser
	if req.Header.Get("ns-server-ui") == "yes" {
		token, err := req.Cookie("ui-auth-q")
		if err != nil {
			panic("ui-auth-q cookie is required")
		}
		if rt.info == nil {
			for _, user := range rt.users {
				if user.password == token.Value {
					foundUser = &user
					break
				}
			}
		} else {
			user, err1 := req.Cookie("user")
			domain, err2 := req.Cookie("domain")
			if err1 == nil && err2 == nil {
				foundUser =
					&testingUser{user: user.Value,
						domain: domain.Value}
			} else {
				log.Fatal("Error parsing user and domain")
			}
		}
	} else {
		username, password, ok := req.BasicAuth()
		if !ok {
			log.Fatal("Need basic auth header")
		}
		for _, user := range rt.users {
			if user.password == password &&
				user.user == username {
				foundUser = &user
				break
			}
		}
	}

	if foundUser != nil {
		response := fmt.Sprintf(`{"user": "%s", "domain": "%s"}`,
			foundUser.user, foundUser.domain)
		return respond(req, 200, response), nil
	}
	return respond(req, 401, ""), nil
}

func (rt *testingRoundTripper) setTripped() {
	if !rt.disableSerialChecks {
		rt.tripped = true
	}
}

func (rt *testingRoundTripper) resetTripped() {
	if !rt.disableSerialChecks {
		rt.tripped = false
	}
}

func (rt *testingRoundTripper) assertTripped(t *testing.T, expected bool) {
	if rt.disableSerialChecks {
		return
	} else if rt.tripped != expected {
		t.Fatalf("Tripped is not expected. Have: %v, need: %v",
			rt.tripped, expected)
	}
}

func (rt *testingRoundTripper) addUser(user, domain, password string) {
	u := testingUser{user: user, domain: domain, password: password}
	rt.users = append(rt.users, u)
}

func TestStaleBasic(t *testing.T) {
	for _, period := range []time.Duration{1, 0} {
		a := newAuth(period)
		_, err := a.Auth("asd", "bsd")
		if _, ok := err.(*DBStaleError); !ok {
			t.Fatalf("For period: %v expect ErrStale in stale state. Got %v", period, err)
		}
	}
}

func TestStale(t *testing.T) {
	sync1 := make(chan bool)
	sync2 := make(chan bool)

	go func() {
		sync1 <- true
		sync2 <- true
		close(sync2)
	}()

	a := newAuthForTest(func(ch chan struct{}, timeoutBody func()) {
		<-sync1
		go func() {
			<-sync2
			timeoutBody()
		}()
	})

	_, err := a.Auth("a", "b")
	if _, ok := err.(*DBStaleError); !ok {
		t.Fatalf("Expect ErrStale in stale state. Got %v", err)
	}

	if _, ok := <-sync2; ok {
		t.Fatal("Some bad sync")
	}

}

func mkNode(host, user, pwd string, ports []int, local bool) (rv cbauthimpl.Node) {
	rv.Host = host
	rv.User = user
	rv.Password = pwd
	rv.Ports = ports
	rv.Local = local
	return
}

func TestServicePwd(t *testing.T) {
	a := newAuth(0)
	c := cbauthimpl.Cache{
		Nodes: append(cbauthimpl.Cache{}.Nodes,
			mkNode("beta.local", "_admin", "foobar", []int{9000, 12000}, false),
			mkNode("chi.local", "_admin", "barfoo", []int{9001, 12001}, false),
			mkNode("fc00:0::10", "_admin", "barfoo", []int{9000, 12000}, false)),
		SpecialUser: "@component",
	}

	must(a.svc.UpdateDB(&c, nil))
	u, p, err := a.GetMemcachedServiceAuth("unknown:9000")
	if _, ok := err.(UnknownHostPortError); u != "" || p != "" || !ok {
		t.Fatal("Expect error trying to get auth for unknown service")
	}
	u, p, _ = a.GetMemcachedServiceAuth("beta.local:9000")
	if u != "_admin" || p != "foobar" {
		t.Fatalf("Expect valid creds for beta.local:9000. Got: %s:%s", u, p)
	}
	u, p, _ = a.GetMemcachedServiceAuth("chi.local:12001")
	if u != "_admin" || p != "barfoo" {
		t.Fatalf("Expect valid creds for chi.local:12001. Got: %s:%s", u, p)
	}
	u, p, _ = a.GetMemcachedServiceAuth("[fc00::10]:9000")
	if u != "_admin" || p != "barfoo" {
		t.Fatalf("Expect valid creds for [fc00::10]:9000. Got: %s:%s", u, p)
	}

	u, p, _ = a.GetHTTPServiceAuth("chi.local:9001")
	if u != "@component" || p != "barfoo" {
		t.Fatalf("Expect valid http creds for chi.local:9001. Got: %s:%s", u, p)
	}
}

func prepareAuth(rt *testingRoundTripper) *authImpl {
	a := newAuth(0)
	a.setTransport(rt)

	must(a.svc.UpdateDB(newCache(a), nil))
	return a
}

func assertEqual(t *testing.T, name, expect, actual string) {
	if expect != actual {
		t.Errorf("Expect %v to be %v, Got %v", name, expect, actual)
	}
}

func assertCreds(t *testing.T, c Creds, name, domain string) {
	assertEqual(t, "Name", name, c.Name())
	assertEqual(t, "Domain", domain, c.Domain())
	if !acc(c.IsAllowed(name)) {
		t.Errorf("Expect permission %v to be granted", name)
	}
	if acc(c.IsAllowed("something else")) {
		t.Errorf("Expect permissions other than %v not to be granted",
			name)
	}
}

func getBasicAuthRequest(user, password string) *http.Request {
	req, err := http.NewRequest("GET", "http://q:11234/_whatever", nil)
	must(err)
	req.SetBasicAuth(user, password)
	return req
}

func basicAuthRequest(a *authImpl, user, password string) (Creds, error) {
	return a.AuthWebCreds(getBasicAuthRequest(user, password))
}

func assertAuthFailure(t *testing.T, c Creds, err error) {
	if err == nil {
		t.Errorf("Should not be authenticated. Creds = %v", c)
	}
	assertEqual(t, "error", "Authentication failure", err.Error())
}

func onBehalfRequest(a *authImpl, user, password, onBehalfUser,
	onBehalfDomain string) (Creds, error) {
	req := getBasicAuthRequest(user, password)
	data := []byte(onBehalfUser + ":" + onBehalfDomain)
	req.Header.Set("cb-on-behalf-of",
		base64.StdEncoding.EncodeToString(data))
	return a.AuthWebCreds(req)
}

func TestBasicAuth(t *testing.T) {
	rt := newTestingRT(t)
	rt.addUser("user1", "local", "asdasd")

	a := prepareAuth(rt)

	c, err := basicAuthRequest(a, "user1", "asdasd")
	must(err)
	rt.assertTripped(t, true)
	assertCreds(t, c, "user1", "local")
	rt.resetTripped()

	c, err = basicAuthRequest(a, "user1", "asdasd")
	must(err)
	rt.assertTripped(t, false)
	assertCreds(t, c, "user1", "local")

	c, err = basicAuthRequest(a, "user1", "wrong")
	rt.assertTripped(t, true)
	assertAuthFailure(t, c, err)
}

func TestOnBehalf(t *testing.T) {
	rt := newTestingRT(t)
	rt.addUser("admin", "admin", "pwd")
	rt.addUser("joe", "local", "pwd")
	rt.addUser("puppet", "local", "asdasd")

	a := prepareAuth(rt)
	c, err := onBehalfRequest(a, "admin", "pwd", "puppet", "local")
	must(err)
	rt.assertTripped(t, true)
	assertCreds(t, c, "puppet", "local")
	rt.resetTripped()

	c, err = onBehalfRequest(a, "joe", "pwd", "puppet", "local")
	rt.assertTripped(t, true)
	assertAuthFailure(t, c, err)
	rt.resetTripped()

	c, err = onBehalfRequest(a, "admin", "wrong", "puppet", "local")
	rt.assertTripped(t, true)
	assertAuthFailure(t, c, err)
}

func TestTokenAdmin(t *testing.T) {
	rt := newTestingRT(t)
	rt.addUser("Administrator", "admin", "1234567890")

	a := prepareAuth(rt)

	req, err := http.NewRequest("GET", "http://q:11234/_queryStatsmaybe", nil)
	must(err)
	req.Header.Set("Cookie", "ui-auth-q=1234567890")
	req.Header.Set("ns-server-ui", "yes")

	c, err := a.AuthWebCreds(req)
	must(err)
	rt.assertTripped(t, true)
	assertCreds(t, c, "Administrator", "builtin")
}

func initTestHandleGetRequestParams(info *GetReqTestInfo) {
	info.bucketsHit = make(map[ReqKey]bool)
	info.bucketsMap = make(map[ReqKey][]string)
	info.permHit = make(map[ReqKeyPerm]bool)
	info.permMap = make(map[ReqKeyPerm]bool)
	info.uuidHit = make(map[ReqKey]bool)
	info.uuidMap = make(map[ReqKey]string)

	info.domains = []string{"admin", "local", "external"}
	info.users = []string{"user0", "Administrator", "br", "testing", "12ekf293fk"}
	info.permissions = []string{"cluster.bucket[default].data!read",
		"cluster.bucket[default].data!write"}

	buckets := []string{"N1QL", "travel-sample", "non-sequitur"}

	for i, domain := range info.domains {
		for j, user := range info.users {
			key := ReqKey{user: user, domain: domain}
			bkts := []string{}
			index := i + j + 1
			if index%2 == 0 {
				bkts = append(bkts, buckets[0])
			}
			if index%3 == 0 {
				bkts = append(bkts, buckets[1])
			}
			if index%5 == 0 {
				bkts = append(bkts, buckets[2])
			}

			info.bucketsMap[key] = bkts
			if domain == "local" {
				letter := string(rune(65 + index))
				info.uuidMap[key] = strings.Repeat(letter, 8)
			}

			permKey := ReqKeyPerm{user: user, domain: domain,
				permission: info.permissions[index%2]}
			info.permMap[permKey] = true
		}
	}
	info.numCombos = len(info.domains) * len(info.users) *
		len(info.permissions)
}

func getRequestBuckets(rt *testingRoundTripper, a *authImpl, user, domain string) {
	key := ReqKey{user: user, domain: domain}
	cacheMiss := !rt.info.bucketsHit[key]
	testStr := fmt.Sprintf("GetUserBuckets(%s %s)", user, domain)

	rt.resetTripped()
	bkts, err := a.GetUserBuckets(user, domain)
	rt.assertTripped(rt.t, cacheMiss)

	if err != nil {
		rt.t.Fatalf("%s failed with: %s", testStr, err)
	}
	if !reflect.DeepEqual(bkts, rt.info.bucketsMap[key]) {
		rt.t.Fatalf("%s incorrect. Expected:%s Got:%s cacheMiss:%t",
			testStr, rt.info.bucketsMap[key], bkts, cacheMiss)
	}
	rt.t.Logf("%s request returned:%s cacheMiss:%t", testStr, bkts, cacheMiss)
}

func getRequestUuid(rt *testingRoundTripper, a *authImpl, user, domain string) {
	key := ReqKey{user: user, domain: domain}
	cacheMiss := domain == "local" && !rt.info.uuidHit[key]
	testStr := fmt.Sprintf("GetUserUuid(%s %s)", user, domain)

	rt.resetTripped()
	uuid, err := a.GetUserUuid(user, domain)
	rt.assertTripped(rt.t, cacheMiss)

	if uuid == "" && err != ErrNoUuid {
		rt.t.Fatalf("%s did not fail with: %s", testStr, ErrNoUuid)
	}
	if uuid != rt.info.uuidMap[key] {
		rt.t.Fatalf("%s incorrect. Expected:%s Got:%s cacheMiss:%t",
			testStr, rt.info.uuidMap[key], uuid, cacheMiss)
	}
	rt.t.Logf("%s request returned:%s cacheMiss:%t", testStr, uuid, cacheMiss)
}

func getRequestPerm(rt *testingRoundTripper, a *authImpl, user, domain, perm string) {
	// This request is used only to initialize Creds to the user, domain to call
	// Creds.IsAllowed (to exercise checkPermission cache).
	req, err := http.NewRequest("GET", "http://q:11234/_queryStatsmaybe", nil)
	must(err)
	cookieStr := fmt.Sprintf("ui-auth-q=1234567890;user=%s;domain=%s", user, domain)
	req.Header.Set("Cookie", cookieStr)
	req.Header.Set("ns-server-ui", "yes")
	rt.resetTripped()
	c, err := a.AuthWebCreds(req)
	must(err)
	rt.assertTripped(rt.t, true)

	permKey := ReqKeyPerm{user: user, domain: domain,
		permission: perm}
	cacheMiss := !rt.info.permHit[permKey] || domain == "external"
	testStr := fmt.Sprintf("IsAllowed(%s %s %s)", user, domain, perm)

	rt.resetTripped()
	result, err := c.IsAllowed(perm)
	rt.assertTripped(rt.t, cacheMiss)

	if err != nil {
		rt.t.Fatalf("%s failed with: %s", testStr, err)
	}
	if result != rt.info.permMap[permKey] {
		rt.t.Fatalf("%s incorrect. Expected:%t Got:%t cacheMiss:%t",
			testStr, rt.info.permMap[permKey], result, cacheMiss)
	}
	rt.t.Logf("%s request returned:%t cacheMiss:%t", testStr, result, cacheMiss)
}

func testHandleGetRequestCore(rt *testingRoundTripper, a *authImpl) {
	// Test each valid combination at least twice to exercise
	// both the HTTP request and cache hit paths.
	// Exercise non-existent keys sporadically, these will return:
	// GetUserBuckets - empty list of buckets, no error
	// GetUserUuid - "" Uuid, ErrorNoUuid
	// IsAllowed - false permission, no error
	for i := 0; i < 3*rt.info.numCombos; i++ {
		temp := i
		perm_idx := temp % len(rt.info.permissions)
		perm := rt.info.permissions[perm_idx]
		temp /= len(rt.info.permissions)
		user_idx := temp % len(rt.info.users)
		user := rt.info.users[user_idx]
		temp /= len(rt.info.users)
		domain_idx := temp % len(rt.info.domains)
		domain := rt.info.domains[domain_idx]

		getRequestBuckets(rt, a, user, domain)
		getRequestUuid(rt, a, user, domain)
		getRequestPerm(rt, a, user, domain, perm)

		if i%10 == 0 {
			domain = "bogus"
			getRequestBuckets(rt, a, user, domain)
			getRequestUuid(rt, a, user, domain)
			getRequestPerm(rt, a, user, domain, perm)
		}
	}
}

/*
 * Tests GetUserUuid(), GetUserBuckets(), IsAllowed() GET requests.
 * Requests are served from the cache unless the underlying permissions
 * or uuid have changed (as indicated by a version mismatch).
 * For sequential requests, it verifies that the request hits or misses
 * the cache (cache misses are fielded by the server, setting "tripped").
 * When multiple routines run, it only validates the returned result is
 * correct; it doesn't confirm whether the request hit the cache/server.
 */
func TestGetProcessRequest(t *testing.T) {
	rt := newTestingRT(t)
	a := newAuth(0)
	a.setTransport(rt)

	var cache *cbauthimpl.Cache = newCache(a)
	cache.PermissionsVersion = "abc"
	cache.UserVersion = "def"
	must(a.svc.UpdateDB(cache, nil))

	rt.info = &GetReqTestInfo{}
	initTestHandleGetRequestParams(rt.info)
	testHandleGetRequestCore(rt, a)

	// Modify permissions version which should invalidate cache entries
	// for GetUserBuckets and IsAllowed
	cache.PermissionsVersion = "def"
	must(a.svc.UpdateDB(cache, nil))
	rt.info.bucketsHit = make(map[ReqKey]bool)
	rt.info.permHit = make(map[ReqKeyPerm]bool)
	testHandleGetRequestCore(rt, a)

	// Modify user version which should invalidate cache entries
	// for GetUserUuid
	cache.UserVersion = "abc"
	must(a.svc.UpdateDB(cache, nil))
	rt.info.uuidHit = make(map[ReqKey]bool)
	testHandleGetRequestCore(rt, a)

	// Before running concurrent goroutines, disable serial checks
	// that set/read unprotected shared variables in rt
	// Reset the versions to purge caches and encourage concurrent
	// cache adds in addition to reads
	rt.disableSerialChecks = true
	cache.PermissionsVersion = "123"
	cache.UserVersion = "456"
	must(a.svc.UpdateDB(cache, nil))

	var wg sync.WaitGroup
	for i := 1; i <= 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(1 * time.Microsecond)
			testHandleGetRequestCore(rt, a)
		}()
	}
	wg.Wait()
}

func TestUnknownHostPortErrorFormatting(t *testing.T) {
	t.Log("Error: ", UnknownHostPortError("asdsd").Error())
}

func TestStaleErrorFormatting(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Path := r.URL.Path
		if Path == "/unauthenticated" {
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer s.Close()

	oldDef := revrpc.DefaultBabysitErrorPolicy.(revrpc.DefaultErrorPolicy)
	defer func() {
		revrpc.DefaultBabysitErrorPolicy = oldDef
	}()
	tmpDef := oldDef
	tmpDef.RestartsToExit = 1
	revrpc.DefaultBabysitErrorPolicy = tmpDef

	commonPrefix := "CBAuth database is stale: last reason: "
	notFoundErr := commonPrefix + "Need 200 status!. Got 404"
	CheckStaleErrorFormatting(t, s.URL+"/test", notFoundErr)
	invalidCredsErr := commonPrefix + "invalid revrpc credentials"
	CheckStaleErrorFormatting(t, s.URL+"/unauthenticated", invalidCredsErr)
}

func CheckStaleErrorFormatting(t *testing.T, URL string, expectedErrorPrefix string) {
	rpcsvc := revrpc.MustService(URL)
	a := newAuth(10 * time.Second)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		runRPCForSvc(rpcsvc, a.svc, getCbauthErrorPolicy(a.svc, false))
		wg.Done()
	}()

	_, err := a.Auth("", "")
	se, ok := err.(*DBStaleError)
	if !ok {
		t.Fatalf("Expected stale error. Got: %s", err)
	}
	errString := se.Error()
	t.Log("error string: ", errString)
	if errString[:len(expectedErrorPrefix)] != expectedErrorPrefix {
		t.Fatalf("Expecting specific prefix of stale error. Got %s", errString)
	}
	wg.Wait()
}
