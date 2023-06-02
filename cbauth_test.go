package cbauth

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
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
	}
}

type testingUser struct {
	user     string
	domain   string
	password string
}

type testingRoundTripper struct {
	t       *testing.T
	baseURL string
	users   []testingUser
	tripped bool
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

	statusCode := 401

	// for simplicity let's grant the permission that matches the username
	if permission[0] == user[0] {
		statusCode = 200
	}

	// granted to admins for on-behalf to work
	if permission[0] == "cluster.admin.security.admin!impersonate" &&
		domain[0] == "admin" {
		statusCode = 200
	}

	return respond(req, statusCode, ""), nil
}

func (rt *testingRoundTripper) resetTripped() {
	rt.tripped = false
}

func (rt *testingRoundTripper) authRoundTrip(req *http.Request) (
	res *http.Response, err error) {
	if rt.tripped {
		log.Fatalf("Already tripped")
	}

	rt.tripped = true

	var foundUser *testingUser
	if req.Header.Get("ns-server-ui") == "yes" {
		token, err := req.Cookie("ui-auth-q")
		if err != nil {
			panic("ui-auth-q cookie is required")
		}
		for _, user := range rt.users {
			if user.password == token.Value {
				foundUser = &user
				break
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

func (rt *testingRoundTripper) assertTripped(t *testing.T, expected bool) {
	if rt.tripped != expected {
		t.Fatalf("Tripped is not expected. Have: %v, need: %v", rt.tripped, expected)
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

func TestUnknownHostPortErrorFormatting(t *testing.T) {
	t.Log("Error: ", UnknownHostPortError("asdsd").Error())
}

func TestStaleErrorFormatting(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer s.Close()

	rpcsvc := revrpc.MustService(s.URL + "/test")
	a := newAuth(10 * time.Second)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		oldDef := revrpc.DefaultBabysitErrorPolicy.(revrpc.DefaultErrorPolicy)
		defer func() {
			revrpc.DefaultBabysitErrorPolicy = oldDef
		}()
		tmpDef := oldDef
		tmpDef.RestartsToExit = 1
		revrpc.DefaultBabysitErrorPolicy = tmpDef
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
	expectedString := "CBAuth database is stale: last reason: Need 200 status!. Got "
	if errString[:len(expectedString)] != expectedString {
		t.Fatalf("Expecting specific prefix of stale error. Got %s", errString)
	}
	wg.Wait()
}
