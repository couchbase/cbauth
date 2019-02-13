// @author Couchbase <info@couchbase.com>
// @copyright 2018-2019 Couchbase, Inc.
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

// +build !race

package utils

import (
	"math/rand"
	"sync"
	"testing"
)

func TestOneItem(t *testing.T) {
	var wg sync.WaitGroup

	size := 256
	threads := 10000
	hits := 10000

	c := NewCache(size)

	c.Add("aa", "bb")

	wg.Add(threads)

	for i := 0; i < threads; i++ {
		go func(num int) {
			defer wg.Done()
			for j := 0; j < hits; j++ {
				_, success := c.Get("aa")
				if !success {
					t.Fatal("not found")
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestChaos(t *testing.T) {
	var wg sync.WaitGroup

	size := 250
	values := 250
	threads := 10000
	hits := 10000

	c := NewCache(size)

	misses := make([]int, threads)

	wg.Add(threads)

	for i := 0; i < values; i++ {
		c.Add(i, i+13)
	}

	for i := 0; i < threads; i++ {
		go func(num int, key int) {
			defer wg.Done()

			for j := 0; j < hits; j++ {
				key = key + 1
				if key >= values {
					key = 0
				}
				value := key + 13

				res, success := c.Get(key)
				if !success {
					misses[num] = misses[num] + 1
					c.Add(key, value)
				} else if res != value {
					t.Fatalf("value mismatch %d != %d",
						res, value)
				}
			}
		}(i, rand.Intn(values))
	}
	wg.Wait()

	totalHits := hits * threads
	totalMisses := 0
	for _, s := range misses {
		totalMisses += s
	}
	t.Logf("Hits: %d, Misses: %d", totalHits, totalMisses)
}
