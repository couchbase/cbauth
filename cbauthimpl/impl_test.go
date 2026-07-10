// @author Couchbase <info@couchbase.com>
// @copyright 2019 Couchbase, Inc.
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

package cbauthimpl

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"sync"
	"testing"
	"time"
)

var (
	readerConfigs = []int{10, 100, 1000, 10000}
)

func newSvc() *Svc {
	svc := NewSVC(time.Duration(0), errors.New("blah"))
	// Pretend that we have a fresh creds database.
	updateDB(svc)

	return svc
}

func updateDB(svc *Svc) {
	svc.UpdateDB(&Cache{}, nil)
}

func runReaders(svc *Svc, b *testing.B) {
	for _, desiredReaders := range readerConfigs {
		maxprocs := runtime.GOMAXPROCS(0)
		parallelism := 1 + (desiredReaders-1)/maxprocs
		readers := parallelism * maxprocs

		name := fmt.Sprintf("readers = %d", readers)
		b.Run(name, func(b *testing.B) {
			b.SetParallelism(parallelism)
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					_ = fetchDB(svc)
				}
			})
		})
	}
}

func BenchmarkFetchDB_RO(b *testing.B) {
	runReaders(newSvc(), b)
}

func BenchmarkFetchDB_RWMeasureReaders(b *testing.B) {
	svc := newSvc()

	die := make(chan struct{})
	done := &sync.WaitGroup{}
	done.Add(1)

	go func() {
		defer done.Done()

		for {
			select {
			case <-die:
				return
			default:
				updateDB(svc)
			}
		}
	}()

	defer func() {
		close(die)
		done.Wait()
	}()

	runReaders(svc, b)
}

func BenchmarkFetchDB_RWMeasureWriter(b *testing.B) {
	svc := newSvc()

	for _, readers := range readerConfigs {
		name := fmt.Sprintf("readers = %d", readers)

		b.Run(name, func(b *testing.B) {
			// Stop the timer while we start the readers, so it's
			// not included in the measured time.
			b.StopTimer()

			die := make(chan struct{})

			started := &sync.WaitGroup{}
			started.Add(readers)

			done := &sync.WaitGroup{}
			done.Add(readers)

			for i := 0; i < readers; i++ {
				go func() {
					started.Done()
					defer done.Done()

					for {
						select {
						case <-die:
							return
						default:
							_ = fetchDB(svc)
						}
					}
				}()
			}

			defer func() {
				// Don't include readers termination into
				// measured time.
				b.StopTimer()

				close(die)
				done.Wait()
			}()

			// Make sure readers have started before turning the
			// timer back on.
			started.Wait()
			b.StartTimer()

			for i := 0; i < b.N; i++ {
				updateDB(svc)
			}
		})
	}
}

func TestMatchHost(t *testing.T) {
	tests := []struct {
		name  string
		node  Node
		host  string
		match bool
	}{
		{name: "Hostname", host: "foo.local", node: Node{Host: "foo.local"}, match: true},
		{name: "DifferentHostname", host: "foo.local", node: Node{Host: "bar.local"}},
		{name: "IP", host: "199.193.192.229", node: Node{Host: "199.193.192.229"}, match: true},
		{name: "DifferentIP", host: "151.101.64.81", node: Node{Host: "199.193.192.229"}},
		{name: "HostnameIP", host: "151.101.64.81", node: Node{Host: "test.local"}},
		{name: "IPHostname", host: "test.local", node: Node{Host: "151.101.64.81"}},
		{name: "LoopbackIPv4Local", host: "127.0.0.1", node: Node{Host: "foo.local", Local: true}, match: true},
		{name: "LoopbackIPv4NotLocal", host: "127.0.0.1", node: Node{Host: "foo.local"}},
		{name: "LoopbackIPv6Local", host: "::1", node: Node{Host: "foo.local", Local: true}, match: true},
		{name: "LoopbackIPv6NotLocal", host: "::1", node: Node{Host: "foo.local"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if matchHost(test.node, test.host) != test.match {
				t.Errorf("Expected match %v, got %v", test.match, !test.match)
			}
		})
	}
}

// fakeResponse builds an *http.Response with the given status code and JSON body.
func fakeResponse(statusCode int, body interface{}) *http.Response {
	b, _ := json.Marshal(body)
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(bytes.NewReader(b)),
		Header:     make(http.Header),
	}
}

func TestProcessResponseCredential_AWS(t *testing.T) {
	wire := map[string]interface{}{
		"id":            "backup/aws/prod",
		"type":          "aws",
		"schemaVersion": 1,
		"meta": map[string]interface{}{
			"createdAt": 1740000000000,
			"createdBy": map[string]interface{}{
				"user":   "admin",
				"domain": "local",
			},
			"description": "production AWS creds",
			"guardrails": map[string]interface{}{
				"allowedServices": []string{
					"n1ql", "backup",
				},
				"urlWhitelist": map[string]interface{}{
					"allAccess":      false,
					"allowedUrls":    []string{"https://s3.amazonaws.com/*"},
					"disallowedUrls": []string{"https://bad.example.com"},
				},
				"allowedOperations": []string{
					"READ", "WRITE",
				},
			},
		},
		"fields": map[string]interface{}{
			"accessKeyId":     "AKIAIOSFODNN7EXAMPLE",
			"secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			"region":          "us-east-1",
			"sessionToken":    "tok123",
		},
	}
	resp := fakeResponse(200, wire)
	val, err := processResponseCredential(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cred := val.(*Credential)
	if cred.ID != "backup/aws/prod" {
		t.Errorf("ID = %q, want %q",
			cred.ID, "backup/aws/prod")
	}
	if cred.Type != "aws" {
		t.Errorf("Type = %q, want %q", cred.Type, "aws")
	}
	if cred.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1",
			cred.SchemaVersion)
	}
	if cred.Meta.Description != "production AWS creds" {
		t.Errorf("Meta.Description = %q",
			cred.Meta.Description)
	}
	if cred.Meta.CreatedBy.User != "admin" ||
		cred.Meta.CreatedBy.Domain != "local" {
		t.Errorf("Meta.CreatedBy = %+v",
			cred.Meta.CreatedBy)
	}
	if len(cred.Meta.Guardrails.AllowedServices) != 2 ||
		cred.Meta.Guardrails.AllowedServices[0] != "n1ql" {
		t.Errorf(
			"Meta.Guardrails.AllowedServices = %v",
			cred.Meta.Guardrails.AllowedServices)
	}
	if len(cred.Meta.Guardrails.AllowedOperations) != 2 {
		t.Errorf(
			"Meta.Guardrails.AllowedOperations = %v",
			cred.Meta.Guardrails.AllowedOperations)
	}
	wl := cred.Meta.Guardrails.URLWhitelist
	if wl == nil {
		t.Fatal("URLWhitelist is nil")
	}
	if wl.AllAccess {
		t.Error("URLWhitelist.AllAccess should be false")
	}
	if len(wl.AllowedURLs) != 1 ||
		wl.AllowedURLs[0] != "https://s3.amazonaws.com/*" {
		t.Errorf("URLWhitelist.AllowedURLs = %v",
			wl.AllowedURLs)
	}
	if len(wl.DisallowedURLs) != 1 ||
		wl.DisallowedURLs[0] != "https://bad.example.com" {
		t.Errorf("URLWhitelist.DisallowedURLs = %v",
			wl.DisallowedURLs)
	}
	if cred.AWS == nil {
		t.Fatal("AWS payload is nil")
	}
	if cred.AWS.AccessKeyID != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("AWS.AccessKeyID = %q",
			cred.AWS.AccessKeyID)
	}
	if cred.AWS.SecretAccessKey !=
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" {
		t.Errorf("AWS.SecretAccessKey = %q",
			cred.AWS.SecretAccessKey)
	}
	if cred.AWS.Region != "us-east-1" {
		t.Errorf("AWS.Region = %q", cred.AWS.Region)
	}
	if cred.AWS.SessionToken != "tok123" {
		t.Errorf("AWS.SessionToken = %q",
			cred.AWS.SessionToken)
	}
	if cred.HTTP != nil || cred.Couchbase != nil ||
		cred.AzureShared != nil || cred.AzureAD != nil ||
		cred.AzureSAS != nil ||
		cred.AzureManaged != nil || cred.GCP != nil {
		t.Error("non-AWS payload field is non-nil")
	}
}

func TestProcessResponseCredential_URLWhitelistAllAccess(
	t *testing.T,
) {
	wire := map[string]interface{}{
		"id":            "open-cred",
		"type":          "http",
		"schemaVersion": 1,
		"meta": map[string]interface{}{
			"createdAt": 1740000000000,
			"createdBy": map[string]interface{}{
				"user": "admin", "domain": "local",
			},
			"guardrails": map[string]interface{}{
				"allowedServices": []string{"n1ql"},
				"urlWhitelist": map[string]interface{}{
					"allAccess": true,
				},
			},
		},
		"fields": map[string]interface{}{
			"authScheme": "bearer",
			"token":      "tok",
		},
	}
	resp := fakeResponse(200, wire)
	val, err := processResponseCredential(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cred := val.(*Credential)
	wl := cred.Meta.Guardrails.URLWhitelist
	if wl == nil {
		t.Fatal("URLWhitelist is nil")
	}
	if !wl.AllAccess {
		t.Error("URLWhitelist.AllAccess should be true")
	}
	if len(wl.AllowedURLs) != 0 {
		t.Errorf("URLWhitelist.AllowedURLs = %v",
			wl.AllowedURLs)
	}
}

func TestProcessResponseCredential_NoURLWhitelist(
	t *testing.T,
) {
	wire := map[string]interface{}{
		"id":            "no-url-cred",
		"type":          "aws",
		"schemaVersion": 1,
		"meta": map[string]interface{}{
			"createdAt": 1740000000000,
			"createdBy": map[string]interface{}{
				"user": "admin", "domain": "local",
			},
			"guardrails": map[string]interface{}{
				"allowedServices": []string{"backup"},
			},
		},
		"fields": map[string]interface{}{
			"accessKeyId":     "AK",
			"secretAccessKey": "SK",
			"region":          "us-east-1",
		},
	}
	resp := fakeResponse(200, wire)
	val, err := processResponseCredential(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cred := val.(*Credential)
	if cred.Meta.Guardrails.URLWhitelist != nil {
		t.Error("URLWhitelist should be nil when absent")
	}
}

func TestProcessResponseCredential_HTTP(t *testing.T) {
	wire := map[string]interface{}{
		"id":            "stripe-key",
		"type":          "http",
		"schemaVersion": 1,
		"meta": map[string]interface{}{
			"createdAt": 1740000000000,
			"createdBy": map[string]interface{}{
				"user": "admin", "domain": "local",
			},
		},
		"fields": map[string]interface{}{
			"authScheme": "bearer",
			"token":      "sk_live_secret",
			"headerName": "Authorization",
		},
	}
	resp := fakeResponse(200, wire)
	val, err := processResponseCredential(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cred := val.(*Credential)
	if cred.HTTP == nil {
		t.Fatal("HTTP payload is nil")
	}
	if cred.HTTP.AuthScheme != "bearer" {
		t.Errorf("HTTP.AuthScheme = %q", cred.HTTP.AuthScheme)
	}
	if cred.HTTP.Token != "sk_live_secret" {
		t.Errorf("HTTP.Token = %q", cred.HTTP.Token)
	}
	if cred.HTTP.HeaderName != "Authorization" {
		t.Errorf("HTTP.HeaderName = %q", cred.HTTP.HeaderName)
	}
	if cred.AWS != nil {
		t.Error("AWS should be nil for http type")
	}
}

func TestProcessResponseCredential_GCPHmac(t *testing.T) {
	wire := map[string]interface{}{
		"id":            "gcp-backup",
		"type":          "gcp",
		"schemaVersion": 1,
		"meta": map[string]interface{}{
			"createdAt": 1740000000000,
			"createdBy": map[string]interface{}{
				"user": "admin", "domain": "local",
			},
		},
		"fields": map[string]interface{}{
			"accessKeyId":     "GOOG123",
			"secretAccessKey": "SECRET",
			"region":          "us-central1",
		},
	}
	resp := fakeResponse(200, wire)
	val, err := processResponseCredential(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cred := val.(*Credential)
	if cred.GCP == nil {
		t.Fatal("GCP payload is nil")
	}
	if cred.GCP.AccessKeyID != "GOOG123" {
		t.Errorf("GCP.AccessKeyID = %q", cred.GCP.AccessKeyID)
	}
	if cred.GCP.SecretAccessKey != "SECRET" {
		t.Errorf("GCP.SecretAccessKey = %q", cred.GCP.SecretAccessKey)
	}
	if cred.GCP.Region != "us-central1" {
		t.Errorf("GCP.Region = %q", cred.GCP.Region)
	}
}

func TestProcessResponseCredential_GCPSa(t *testing.T) {
	wire := map[string]interface{}{
		"id":            "gcp-sa-prod",
		"type":          "gcp",
		"schemaVersion": 1,
		"meta": map[string]interface{}{
			"createdAt": 1740000000000,
			"createdBy": map[string]interface{}{
				"user": "admin", "domain": "local",
			},
		},
		"fields": map[string]interface{}{
			"jsonCredentials": `{"type":"service_account","project_id":"my-proj"}`,
			"region":          "us-east1",
		},
	}
	resp := fakeResponse(200, wire)
	val, err := processResponseCredential(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cred := val.(*Credential)
	if cred.GCP == nil {
		t.Fatal("GCP payload is nil")
	}
	if cred.GCP.JSONCredentials != `{"type":"service_account","project_id":"my-proj"}` {
		t.Errorf("GCP.JSONCredentials = %q", cred.GCP.JSONCredentials)
	}
	if cred.GCP.Region != "us-east1" {
		t.Errorf("GCP.Region = %q", cred.GCP.Region)
	}
	// HMAC fields should be empty for a service-account credential.
	if cred.GCP.AccessKeyID != "" || cred.GCP.SecretAccessKey != "" {
		t.Error("HMAC fields should be empty for service-account mode")
	}
}

func TestProcessResponseCredential_AWSInstanceMetadata(t *testing.T) {
	wire := map[string]interface{}{
		"id":            "backup/aws/imds",
		"type":          "awsInstanceMetadata",
		"schemaVersion": 1,
		"meta": map[string]interface{}{
			"createdAt": 1740000000000,
			"createdBy": map[string]interface{}{
				"user": "admin", "domain": "local",
			},
		},
		"fields": map[string]interface{}{
			"region":   "us-east-1",
			"endpoint": "https://s3.example.com",
		},
	}
	resp := fakeResponse(200, wire)
	val, err := processResponseCredential(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cred := val.(*Credential)
	if cred.AWSInstanceMetadata == nil {
		t.Fatal("AWSInstanceMetadata payload is nil")
	}
	if cred.AWSInstanceMetadata.Region != "us-east-1" {
		t.Errorf("AWSInstanceMetadata.Region = %q",
			cred.AWSInstanceMetadata.Region)
	}
	if cred.AWSInstanceMetadata.Endpoint != "https://s3.example.com" {
		t.Errorf("AWSInstanceMetadata.Endpoint = %q",
			cred.AWSInstanceMetadata.Endpoint)
	}
}

func TestProcessResponseCredential_UnknownType(t *testing.T) {
	wire := map[string]interface{}{
		"id":            "future-cred",
		"type":          "some_future_type",
		"schemaVersion": 2,
		"meta": map[string]interface{}{
			"createdAt": 1740000000000,
			"createdBy": map[string]interface{}{
				"user": "admin", "domain": "local",
			},
		},
		"fields": map[string]interface{}{
			"foo": "bar",
		},
	}
	resp := fakeResponse(200, wire)
	val, err := processResponseCredential(resp)
	if err != nil {
		t.Fatalf("unexpected error for unknown type: %v", err)
	}
	cred := val.(*Credential)
	if cred.ID != "future-cred" {
		t.Errorf("ID = %q", cred.ID)
	}
	if cred.Type != "some_future_type" {
		t.Errorf("Type = %q", cred.Type)
	}
	// All payload fields should be nil for unknown types.
	if cred.AWS != nil || cred.HTTP != nil || cred.Couchbase != nil {
		t.Error("payload field should be nil for unknown type")
	}
}

func TestProcessResponseCredential_404(t *testing.T) {
	resp := fakeResponse(404, map[string]interface{}{})
	_, err := processResponseCredential(resp)
	if err == nil {
		t.Fatal("expected error for 404")
	}
}

func TestProcessResponseCredential_MetaAuthor(t *testing.T) {
	wire := map[string]interface{}{
		"id":            "test",
		"type":          "aws",
		"schemaVersion": 1,
		"meta": map[string]interface{}{
			"createdAt": 1740000000000,
			"createdBy": map[string]interface{}{"user": "admin", "domain": "local"},
			"updatedAt": 1740000001000,
			"updatedBy": map[string]interface{}{"user": "ops", "domain": "external"},
		},
		"fields": map[string]interface{}{
			"accessKeyId":     "AK",
			"secretAccessKey": "SK",
			"region":          "eu-west-1",
		},
	}
	resp := fakeResponse(200, wire)
	val, err := processResponseCredential(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cred := val.(*Credential)
	if cred.Meta.CreatedBy.User != "admin" || cred.Meta.CreatedBy.Domain != "local" {
		t.Errorf("CreatedBy = %+v", cred.Meta.CreatedBy)
	}
	if cred.Meta.UpdatedBy == nil {
		t.Fatal("UpdatedBy is nil")
	}
	if cred.Meta.UpdatedBy.User != "ops" || cred.Meta.UpdatedBy.Domain != "external" {
		t.Errorf("UpdatedBy = %+v", cred.Meta.UpdatedBy)
	}
}

func TestUnmarshalCredentialFields_AllTypes(t *testing.T) {
	// Verify every supported type can be dispatched without error.
	types := []CredentialType{
		CredentialTypeAWS, CredentialTypeAWSInstanceMetadata,
		CredentialTypeAzureShared, CredentialTypeAzureAD,
		CredentialTypeAzureSAS, CredentialTypeAzureManaged,
		CredentialTypeGCP, CredentialTypeHTTP, CredentialTypeCouchbase,
	}
	for _, typ := range types {
		t.Run(string(typ), func(t *testing.T) {
			cred := &Credential{}
			err := unmarshalCredentialFields(typ, []byte("{}"), cred)
			if err != nil {
				t.Fatalf("unmarshalCredentialFields(%q, {}) = %v", typ, err)
			}
		})
	}
}
