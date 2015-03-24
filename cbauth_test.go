package cbauth

import (
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/couchbase/cbauth/cbauthimpl"
	"github.com/couchbase/cbauth/revrpc"
)

func newAuth(initPeriod time.Duration) *authImpl {
	return &authImpl{cbauthimpl.NewSVC(initPeriod, &DBStaleError{})}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func hashPassword(password string, salt []byte) []byte {
	h := hmac.New(sha1.New, salt)
	h.Write([]byte(password))
	return h.Sum(nil)
}

func mkUser(user, password, salt string) (u cbauthimpl.User) {
	u.User = user
	u.Salt = []byte(salt)
	u.Mac = hashPassword(password, u.Salt)
	return
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

func assertAdmins(t *testing.T, c Creds, needAdmin, needROAdmin bool) {
	if acc(c.IsAdmin()) != needAdmin {
		t.Fatalf("admin access must be: %v", needAdmin)
	}
	roadmin := !acc(c.IsAdmin()) && c.CanReadAnyMetadata()
	if roadmin != needROAdmin {
		t.Fatalf("ro-admin access must be: %v", needROAdmin)
	}
}

type testingRoundTripper struct {
	method  string
	url     string
	user    string
	source  string
	token   string
	role    string
	tripped bool
}

func newTestingRT(method, uri string) *testingRoundTripper {
	return &testingRoundTripper{
		method: method,
		url:    uri,
	}
}

func (rt *testingRoundTripper) RoundTrip(req *http.Request) (res *http.Response, err error) {
	if rt.tripped {
		log.Fatalf("Already tripped")
	}

	rt.tripped = true

	if req.URL.String() != rt.url {
		log.Fatalf("Bad url: %v != %v", rt.url, req.URL)
	}
	if req.Method != rt.method {
		log.Fatalf("Bad method: %s != %s", rt.method, req.Method)
	}

	statusCode := 200

	if req.Header.Get("ns_server-ui") == "yes" {
		token, err := req.Cookie("ui-auth-q")
		if err != nil || rt.token != token.Value {
			statusCode = 401
		}
	} else {
		log.Fatal("Expect to be called only with ns_server-ui=yes")
	}

	response := ""
	status := "401 Unauthorized"
	if statusCode == 200 {
		response = fmt.Sprintf(`{"role": "%s", "user": "%s", "source": "%s"}`, rt.role, rt.user, rt.source)
		status = "200 OK"
	}

	respBody := ioutil.NopCloser(strings.NewReader(response))

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
	}, nil
}

func (rt *testingRoundTripper) resetTripped() {
	rt.tripped = false
}

func (rt *testingRoundTripper) assertTripped(t *testing.T, expected bool) {
	if rt.tripped != expected {
		t.Fatalf("Tripped is not expected. Have: %v, need: %v", rt.tripped, expected)
	}
}

func (rt *testingRoundTripper) setTokenAuth(user, source, token, role string) {
	rt.token = token
	rt.source = source
	rt.user = user
	rt.role = role
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

func doTestStaleThenAdmin(t *testing.T, updateBeforeTimer bool) {
	timerchan := make(chan bool)
	var freshChan chan struct{}
	a := newAuthForTest(func(ch chan struct{}, timeoutBody func()) {
		freshChan = ch
		go func() {
			<-timerchan
			timeoutBody()
		}()
	})

	updatechan := make(chan bool)
	go func() {
		c := cbauthimpl.Cache{Admin: mkUser("admin", "asdasd", "nacl")}
		<-updatechan
		must(a.svc.UpdateDB(&c, nil))
		<-updatechan
	}()

	go func() {
		freshChan <- struct{}{}
		if !updateBeforeTimer {
			close(timerchan)
			return
		}

		updatechan <- true
		updatechan <- true
		close(timerchan)
	}()

	cred, err := a.Auth("admin", "asdasd")
	if updateBeforeTimer {
		must(err)
		if ok, _ := cred.IsAdmin(); !ok {
			t.Fatal("user admin must be recognised as admin")
		}
	} else {
		if _, ok := err.(*DBStaleError); !ok {
			t.Fatal("db must be stale")
		}
		updatechan <- true
		updatechan <- true
	}

	if _, ok := <-timerchan; ok {
		t.Fatal("timerchan must be closed")
	}

	cred, err = a.Auth("admin", "badpass")
	if err != nil || cred != NoAccessCreds {
		t.Fatalf("badpass must not work. Instead got: %v and %v", cred, err)
	}

	cred, err = a.Auth("admin", "asdasd")
	must(err)
	if ok, _ := cred.IsAdmin(); !ok {
		t.Fatal("user admin must be recognised as admin")
	}
}

func TestStaleThenAdminTimerCase(t *testing.T) {
	doTestStaleThenAdmin(t, false)
}

func TestStaleThenAdminUpdateCase(t *testing.T) {
	doTestStaleThenAdmin(t, true)
}

func TestBucketsAuth(t *testing.T) {
	a := newAuth(0)
	must(a.svc.UpdateDB(&cbauthimpl.Cache{Buckets: map[string]string{"default": "", "foo": "bar"}}, nil))
	c, err := a.Auth("foo", "bar")
	must(err)
	if !acc(c.CanAccessBucket("foo")) {
		t.Fatal("Expect foo access with right pw to work")
	}
	if acc(c.CanAccessBucket("default")) {
		t.Fatal("Expect default access to not work when authed towards foo")
	}
	if acc(c.CanAccessBucket("unknown")) {
		t.Fatal("Expect unknown bucket access to not work")
	}
	assertAdmins(t, c, false, false)

	c, err = a.Auth("foo", "notbar")
	if err != nil || c != NoAccessCreds {
		t.Fatalf("Expect wrong password auth to fail. Got: %v and %v", c, err)
	}

	c, err = a.Auth("", "")
	must(err)
	assertAdmins(t, c, false, false)
	if acc(c.CanAccessBucket("foo")) {
		t.Fatal("Expect foo access to not work under anon auth")
	}
	if !acc(c.CanAccessBucket("default")) {
		t.Fatal("Expect default access to work under anon auth")
	}

	// now somebody deletes no-password default bucket
	must(a.svc.UpdateDB(&cbauthimpl.Cache{Buckets: map[string]string{"foo": "bar"}}, nil))
	c, err = a.Auth("foo", "bar")
	must(err)
	assertAdmins(t, c, false, false)
	if !acc(c.CanAccessBucket("foo")) {
		t.Fatal("Expect foo access to work under right pw")
	}
	// and no password access should not work
	c, err = a.Auth("", "")
	if err != nil || c != NoAccessCreds {
		t.Fatalf("Expect no password access to fail after deletion of default bucket. Got: %v and %v", c, err)
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
			mkNode("chi.local", "_admin", "barfoo", []int{9001, 12001}, false)),
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

	u, p, _ = a.GetHTTPServiceAuth("chi.local:9001")
	if u != "@" || p != "barfoo" {
		t.Fatalf("Expect valid http creds for chi.local:9001. Got: %s:%s", u, p)
	}
}

func overrideDefClient(c *http.Client) func() {
	var old *http.Client
	old, http.DefaultClient = http.DefaultClient, c
	return func() {
		http.DefaultClient = old
	}
}

func TestTokenAdmin(t *testing.T) {
	url := "http://127.0.0.1:9000/_auth"

	tr := newTestingRT("POST", url)
	tr.setTokenAuth("Administrator", "saslauthd", "1234567890", "admin")

	defer overrideDefClient(&http.Client{Transport: tr})()

	a := newAuth(0)
	must(a.svc.UpdateDB(&cbauthimpl.Cache{TokenCheckURL: url}, nil))

	req, err := http.NewRequest("GET", "http://q:11234/_queryStatsmaybe", nil)
	must(err)
	req.Header.Set("Cookie", "ui-auth-q=1234567890")
	req.Header.Set("ns_server-ui", "yes")

	c, err := a.AuthWebCreds(req)
	must(err)
	tr.assertTripped(t, true)

	assertAdmins(t, c, true, false)

	if c.Name() != "Administrator" {
		t.Errorf("Expect name to be Administrator")
	}

	if c.Source() != "saslauthd" {
		t.Errorf("Expect source to be saslauthd. Got %s", c.Source())
	}

	if !acc(c.CanAccessBucket("asdasdasdasd")) {
		t.Errorf("Expected to be able to access all buckets. Failed at asdasdasdasd")
	}
	if !acc(c.CanAccessBucket("ffee")) {
		t.Errorf("Expected to be able to access all buckets. Failed at ffee")
	}
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
		runRPCForSvc(rpcsvc, a.svc)
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
