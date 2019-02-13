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

package utils

import (
	"fmt"
	"math/rand"
	"runtime"
	"sync/atomic"
	"testing"
)

const (
	cacheSize = 10240
)

var (
	threadConfigs  = []int{10, 100, 1000, 10000, 100000}
	hitRateConfigs = []int{100, 99, 95, 90, 80}
)

func BenchmarkCacheGet(b *testing.B) {
	c := NewCache(cacheSize)

	for i := 0; i < cacheSize; i++ {
		c.Add(i, i+13)
	}

	for _, threads := range threadConfigs {
		threads, parallelism := adjustThreads(threads)
		name := fmt.Sprintf("threads = %d", threads)

		b.Run(name, func(b *testing.B) {
			b.SetParallelism(parallelism)
			b.RunParallel(func(pb *testing.PB) {
				key := rand.Intn(cacheSize)
				for pb.Next() {
					v, found := c.Get(key)
					if !found {
						b.Fatalf("%d not found", key)
					}

					if v != key+13 {
						b.Fatalf("bad value %d for %d",
							v, key)
					}

					key = (key + 1) % cacheSize
				}
			})
		})
	}

}

func benchmarkCacheAddGet(b *testing.B, values int, parallelism int) {
	c := NewCache(cacheSize)

	for i := 0; i < values; i++ {
		c.Add(i, i+13)
	}

	b.ResetTimer()

	totalHits := uint64(0)
	totalMisses := uint64(0)

	b.SetParallelism(parallelism)
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		seed := rand.Int63()
		rng := rand.New(rand.NewSource(seed))

		hits := uint64(0)
		misses := uint64(0)

		for pb.Next() {
			key := rng.Intn(values)
			value := key + 13

			res, success := c.Get(key)
			if !success {
				misses++
				c.Add(key, value)
			} else {
				hits++

				if res != value {
					b.Fatalf("value mismatch %d != %d",
						res, value)
				}
			}

		}

		atomic.AddUint64(&totalMisses, misses)
		atomic.AddUint64(&totalHits, hits)
	})

	if testing.Verbose() {
		b.Logf("Hits: %d, Misses: %d, Observed Hit Rate: %.2f%%",
			totalHits, totalMisses,
			100*float32(totalHits)/
				float32(totalHits+totalMisses))
	}
}

func BenchmarkCacheAddGet(b *testing.B) {
	for _, hitRate := range hitRateConfigs {
		values := cacheSize + (100-hitRate)*cacheSize/hitRate

		for _, threads := range threadConfigs {
			threads, parallelism := adjustThreads(threads)

			name := fmt.Sprintf(
				"threads = %d, hit rate = %d%%",
				threads, hitRate)

			b.Run(name, func(b *testing.B) {
				benchmarkCacheAddGet(b, values, parallelism)
			})
		}
	}
}

func BenchmarkCacheAdd(b *testing.B) {
	for _, threads := range threadConfigs {
		threads, parallelism := adjustThreads(threads)
		name := fmt.Sprintf("threads = %d", threads)

		b.Run(name, func(b *testing.B) {
			id := uint32(0)
			totalAdds := uint64(0)

			c := NewCache(cacheSize)
			for i := uint64(0); i < cacheSize; i++ {
				c.Add(i, i)
			}

			b.ResetTimer()

			b.SetParallelism(parallelism)
			b.RunParallel(func(pb *testing.PB) {
				myID := atomic.AddUint32(&id, 1)
				key := uint64(myID) << 32
				adds := uint64(0)

				for pb.Next() {
					added := c.Add(key, key)
					if !added {
						b.Fatalf("%d already exists",
							key)
					}

					key++
				}

				atomic.AddUint64(&totalAdds, adds)
			})
		})
	}
}

func adjustThreads(wanted int) (int, int) {
	maxprocs := runtime.GOMAXPROCS(0)
	parallelism := 1 + (wanted-1)/maxprocs

	return parallelism * maxprocs, parallelism
}
