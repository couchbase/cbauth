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
	"errors"
	"fmt"
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
