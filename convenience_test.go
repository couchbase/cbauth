// @author Couchbase <info@couchbase.com>
// @copyright 2026 Couchbase, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package cbauth

import (
	"encoding/base64"
	"net/http"
	"testing"
)

// stubCreds is a minimal Creds implementation for testing
// SetOnBehalfOfHeaders in isolation from the full auth harness.
type stubCreds struct {
	name   string
	domain string
	extras string
}

func (c *stubCreds) Name() string                            { return c.name }
func (c *stubCreds) Domain() string                          { return c.domain }
func (c *stubCreds) User() (string, string)                  { return c.name, c.domain }
func (c *stubCreds) IsAllowed(string) (bool, error)          { return false, nil }
func (c *stubCreds) IsAllowedInternal(string) (bool, error)  { return false, nil }
func (c *stubCreds) GetBuckets() ([]string, error)           { return nil, nil }
func (c *stubCreds) Expiry() int64                           { return 0 }
func (c *stubCreds) Extras() string                          { return c.extras }
func (c *stubCreds) GetCredential(string) (*Credential, error) { return nil, nil }

var _ Creds = (*stubCreds)(nil)

func newReq(t *testing.T) *http.Request {
	req, err := http.NewRequest("GET", "http://example:8091/whatever", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return req
}

func decode(t *testing.T, s string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64 decode %q: %v", s, err)
	}
	return string(b)
}

func TestSetOnBehalfOfHeaders_NoExtras(t *testing.T) {
	req := newReq(t)
	SetOnBehalfOfHeaders(req, &stubCreds{name: "alice", domain: "local"})

	if got := decode(t, req.Header.Get("cb-on-behalf-of")); got != "alice:local" {
		t.Errorf("cb-on-behalf-of = %q, want %q", got, "alice:local")
	}
	if v := req.Header.Get("cb-on-behalf-extras"); v != "" {
		t.Errorf("cb-on-behalf-extras should be unset when Extras() is empty, got %q", v)
	}
}

func TestSetOnBehalfOfHeaders_WithExtras(t *testing.T) {
	extras := `{"groups":["g1","g2"],"exp":1234567890}`
	req := newReq(t)
	SetOnBehalfOfHeaders(req, &stubCreds{
		name:   "bob",
		domain: "external",
		extras: extras,
	})

	if got := decode(t, req.Header.Get("cb-on-behalf-of")); got != "bob:external" {
		t.Errorf("cb-on-behalf-of = %q, want %q", got, "bob:external")
	}
	if got := decode(t, req.Header.Get("cb-on-behalf-extras")); got != extras {
		t.Errorf("cb-on-behalf-extras = %q, want %q", got, extras)
	}
}

func TestSetOnBehalfOfHeaders_NilCreds(t *testing.T) {
	req := newReq(t)
	SetOnBehalfOfHeaders(req, nil)

	if v := req.Header.Get("cb-on-behalf-of"); v != "" {
		t.Errorf("cb-on-behalf-of should be unset for nil Creds, got %q", v)
	}
	if v := req.Header.Get("cb-on-behalf-extras"); v != "" {
		t.Errorf("cb-on-behalf-extras should be unset for nil Creds, got %q", v)
	}
}

func TestSetOnBehalfOfHeaders_OverwritesExisting(t *testing.T) {
	req := newReq(t)
	req.Header.Set("cb-on-behalf-of", "stale")

	SetOnBehalfOfHeaders(req, &stubCreds{name: "carol", domain: "local"})

	if got := decode(t, req.Header.Get("cb-on-behalf-of")); got != "carol:local" {
		t.Errorf("cb-on-behalf-of = %q, want %q", got, "carol:local")
	}
}
