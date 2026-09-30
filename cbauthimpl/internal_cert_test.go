package cbauthimpl

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// countingTransport answers every request with the same body and counts how
// many actually reached it.
type countingTransport struct {
	body  string
	calls int32
}

func (t *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	atomic.AddInt32(&t.calls, 1)
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(bytes.NewBufferString(t.body)),
		Header:     make(http.Header),
	}, nil
}

func svcAnswering(body string) (*Svc, *countingTransport) {
	svc := NewSVC(time.Duration(0), errors.New("stale"))
	rt := &countingTransport{body: body}
	SetTransport(svc, rt)
	svc.UpdateDB(&Cache{
		AuthCheckURL:           "http://localhost/_cbauth",
		ExtractUserFromCertURL: "http://localhost/_cbauth/extractUserFromCert",
		ClientCertAuthState:    "mandatory",
		SpecialUser:            "@",
		SpecialPasswords:       []string{"pwd"},
	}, nil)
	return svc, rt
}

func certState() *tls.ConnectionState {
	return &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{Raw: []byte("a certificate")}},
	}
}

// ns_server names no user when the certificate is not accepted as proof of
// identity on its own. That must read as "no identity", not as a failure, so
// that AuthWebCredsCore falls through to the authorization header -- which it
// only does on a (nil, nil) return.
func TestNoIdentityFallsThroughAndIsCached(t *testing.T) {
	svc, rt := svcAnswering(`{}`)

	for i := 0; i < 2; i++ {
		creds, err := MaybeGetCredsFromCert(svc, certState())
		if err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
		if creds != nil {
			t.Fatalf("call %d: got creds %+v, want nil", i, creds)
		}
	}

	// Without caching the empty identity this would be one round trip per
	// request, serialised behind the semaphore.
	if got := atomic.LoadInt32(&rt.calls); got != 1 {
		t.Errorf("reached ns_server %d times, want 1", got)
	}
}

// A certificate that does map to someone is unaffected, and is cached as before.
func TestIdentityFromCertIsReturnedAndCached(t *testing.T) {
	svc, rt := svcAnswering(`{"user":"@internal","domain":"admin"}`)

	for i := 0; i < 2; i++ {
		creds, err := MaybeGetCredsFromCert(svc, certState())
		if err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
		if creds == nil {
			t.Fatalf("call %d: got nil creds, want an identity", i)
		}
		name, domain := creds.User()
		if name != "@internal" || domain != "admin" {
			t.Errorf("call %d: got %s/%s", i, name, domain)
		}
	}

	if got := atomic.LoadInt32(&rt.calls); got != 1 {
		t.Errorf("reached ns_server %d times, want 1", got)
	}
}

// verifySpecialCreds is what an internal caller falls back to once its
// certificate stops being accepted on its own. Two passwords is what a
// rotation window looks like; both must be taken.
func TestVerifySpecialCreds(t *testing.T) {
	svc, _ := svcAnswering(`{}`)
	svc.UpdateDB(&Cache{SpecialUser: "@",
		SpecialPasswords: []string{"old", "new"}}, nil)
	db := fetchDB(svc)

	tests := []struct {
		name string
		user string
		pwd  string
		want bool
	}{
		{"first special password", "@", "old", true},
		{"second special password", "@", "new", true},
		{"any internal user name", "@index", "new", true},
		{"wrong password", "@", "nope", false},
		{"non internal user", "bob", "old", false},
		{"empty user", "", "old", false},
	}

	for _, tc := range tests {
		if got := verifySpecialCreds(db, tc.user, tc.pwd); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
