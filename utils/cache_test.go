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

func TestCacheSize(t *testing.T) {
	c := NewCache(cacheSize)

	for i := 0; i < cacheSize*4; i++ {
		ok := c.Add(i, i+13)
		if !ok {
			t.Fatalf("key %d is already in the cache", i)
		}
	}

	found := 0
	for i := 0; i < cacheSize*4; i++ {
		v, ok := c.Get(i)
		if ok {
			found++
			if v != i+13 {
				t.Fatalf("bad value %d for key %d", v, i)
			}
		}
	}

	if found != cacheSize {
		t.Fatalf("bad cache size %d, expected %d", found, cacheSize)
	}
}

func TestCacheSizeIncrease_EmptyCache(t *testing.T) {
	c := NewCache(cacheSize)
	cacheSizeNew := 2 * cacheSize
	c.UpdateSize(cacheSizeNew)
	numEntries := 0
	checkCacheProperties(t, c, cacheSize, cacheSizeNew, numEntries)
}

func TestCacheSizeIncrease_HalfFullCache(t *testing.T) {
	c := NewCache(cacheSize)
	cacheSizeNew := 2 * cacheSize
	numEntries := cacheSize / 2

	for i := 0; i < numEntries; i++ {
		ok := c.Add(i, i+13)
		if !ok {
			t.Fatalf("key %d is already in the cache", i)
		}
	}

	c.UpdateSize(cacheSizeNew)
	checkCacheProperties(t, c, cacheSize, cacheSizeNew, numEntries)

	for i := 0; i < numEntries; i++ {
		if c.keys[i] != i {
			t.Fatalf("wrong key found: found: %d expected: %d", c.keys[i], i)
		}
	}
}

func TestCacheSizeIncrease_FullCacheNoRotation(t *testing.T) {
	c := NewCache(cacheSize)
	cacheSizeNew := 2 * cacheSize
	numEntries := cacheSize

	for i := 0; i < numEntries; i++ {
		ok := c.Add(i, i+13)
		if !ok {
			t.Fatalf("key %d is already in the cache", i)
		}
	}

	c.UpdateSize(cacheSizeNew)
	checkCacheProperties(t, c, cacheSize, cacheSizeNew, numEntries)

	for i := 0; i < numEntries; i++ {
		if c.keys[i] != i {
			t.Fatalf("wrong key found: found: %d expected: %d", c.keys[i], i)
		}
	}
}

func TestCacheSizeIncrease_FullCacheWithRotation(t *testing.T) {
	c := NewCache(cacheSize)
	cacheSizeNew := 2 * cacheSize
	numEntries := cacheSize * 3 / 2

	for i := 0; i < numEntries; i++ {
		ok := c.Add(i, i+13)
		if !ok {
			t.Fatalf("key %d is already in the cache", i)
		}
	}

	c.UpdateSize(cacheSizeNew)
	checkCacheProperties(t, c, cacheSize, cacheSizeNew, cacheSize)

	for i := 0; i < cacheSize; i++ {
		expKey := i + cacheSize/2
		if c.keys[i] != expKey {
			t.Fatalf("wrong key found: found: %d expected: %d",
				c.keys[i], expKey)
		}
	}
}

func TestCacheSizeDecrease_EmptyCache(t *testing.T) {
	c := NewCache(cacheSize)
	cacheSizeNew := cacheSize / 2
	c.UpdateSize(cacheSizeNew)
	numEntries := 0
	checkCacheProperties(t, c, cacheSize, cacheSizeNew, numEntries)
}

func TestCacheSizeDecrease_HalfFullCache_NoDeletion(t *testing.T) {
	c := NewCache(cacheSize)
	cacheSizeNew := cacheSize / 2
	numEntries := cacheSize / 2

	for i := 0; i < numEntries; i++ {
		ok := c.Add(i, i+13)
		if !ok {
			t.Fatalf("key %d is already in the cache", i)
		}
	}

	c.UpdateSize(cacheSizeNew)
	checkCacheProperties(t, c, cacheSize, cacheSizeNew, numEntries)

	for i := 0; i < numEntries; i++ {
		if c.keys[i] != i {
			t.Fatalf("wrong key found: found: %d expected: %d", c.keys[i], i)
		}
	}

	for i := 0; i < numEntries; i++ {
		_, ok := c.Get(i)
		if !ok {
			t.Fatalf("key %d not found in cache after size update", i)
		}
	}
}

func TestCacheSizeDecrease_HalfFullCache_WithDeletion(t *testing.T) {
	c := NewCache(cacheSize)
	cacheSizeNew := 1000
	numEntries := cacheSize / 2

	for i := 0; i < numEntries; i++ {
		ok := c.Add(i, i+13)
		if !ok {
			t.Fatalf("key %d is already in the cache", i)
		}
	}

	c.UpdateSize(cacheSizeNew)
	checkCacheProperties(t, c, cacheSize, cacheSizeNew, cacheSizeNew)

	for i := 0; i < cacheSizeNew; i++ {
		expKey := i + numEntries - cacheSizeNew
		if c.keys[i] != expKey {
			t.Fatalf("wrong key found: found: %d expected: %d",
				c.keys[i], expKey)
		}
	}

	for i := 0; i < numEntries-cacheSizeNew; i++ {
		_, ok := c.Get(i)
		if ok {
			t.Fatalf("key %d is not expected in cache after size update", i)
		}
	}

	for i := numEntries - cacheSizeNew; i < numEntries; i++ {
		_, ok := c.Get(i)
		if !ok {
			t.Fatalf("key %d not found in cache after size update", i)
		}
	}
}

func TestCacheSizeDecrease_FullCacheNoRotation(t *testing.T) {
	c := NewCache(cacheSize)
	cacheSizeNew := 1000
	numEntries := cacheSize

	for i := 0; i < numEntries; i++ {
		ok := c.Add(i, i+13)
		if !ok {
			t.Fatalf("key %d is already in the cache", i)
		}
	}

	c.UpdateSize(cacheSizeNew)
	checkCacheProperties(t, c, cacheSize, cacheSizeNew, cacheSizeNew)

	for i := 0; i < cacheSizeNew; i++ {
		expKey := i + numEntries - cacheSizeNew
		if c.keys[i] != expKey {
			t.Fatalf("wrong key found: found: %d expected: %d",
				c.keys[i], expKey)
		}
	}

	for i := 0; i < numEntries-cacheSizeNew; i++ {
		_, ok := c.Get(i)
		if ok {
			t.Fatalf("key %d is not expected in cache after size update", i)
		}
	}

	for i := numEntries - cacheSizeNew; i < numEntries; i++ {
		_, ok := c.Get(i)
		if !ok {
			t.Fatalf("key %d not found in cache after size update", i)
		}
	}
}

func TestCacheSizeDecrease_FullCacheWithRotation1(t *testing.T) {
	c := NewCache(cacheSize)
	cacheSizeNew := 1000
	numEntries := cacheSize * 3 / 2

	for i := 0; i < numEntries; i++ {
		ok := c.Add(i, i+13)
		if !ok {
			t.Fatalf("key %d is already in the cache", i)
		}
	}

	c.UpdateSize(cacheSizeNew)
	checkCacheProperties(t, c, cacheSize, cacheSizeNew, cacheSizeNew)

	for i := 0; i < cacheSizeNew; i++ {
		expKey := i + numEntries - cacheSizeNew
		if c.keys[i] != expKey {
			t.Fatalf("wrong key found: %d expected: %d",
				c.keys[i], expKey)
		}
	}

	for i := 0; i < numEntries-cacheSizeNew; i++ {
		_, ok := c.Get(i)
		if ok {
			t.Fatalf("key %d is not expected in cache after size update", i)
		}
	}

	for i := numEntries - cacheSizeNew; i < numEntries; i++ {
		_, ok := c.Get(i)
		if !ok {
			t.Fatalf("key %d not found in cache after size update", i)
		}
	}
}

func TestCacheSizeDecrease_FullCacheWithRotation2(t *testing.T) {
	c := NewCache(cacheSize)
	cacheSizeNew := 9000
	numEntries := cacheSize * 3 / 2

	for i := 0; i < numEntries; i++ {
		ok := c.Add(i, i+13)
		if !ok {
			t.Fatalf("key %d is already in the cache", i)
		}
	}

	c.UpdateSize(cacheSizeNew)
	checkCacheProperties(t, c, cacheSize, cacheSizeNew, cacheSizeNew)

	for i := 0; i < cacheSizeNew; i++ {
		expKey := i + numEntries - cacheSizeNew
		if c.keys[i] != expKey {
			t.Fatalf("wrong key found: found: %d expected: %d",
				c.keys[i], expKey)
		}
	}

	for i := 0; i < numEntries-cacheSizeNew; i++ {
		_, ok := c.Get(i)
		if ok {
			t.Fatalf("key %d is not expected in cache after size update", i)
		}
	}

	for i := numEntries - cacheSizeNew; i < numEntries; i++ {
		_, ok := c.Get(i)
		if !ok {
			t.Fatalf("key %d not found in cache after size update", i)
		}
	}
}

func checkCacheProperties(t *testing.T, c *Cache,
	orgMaxSize int, expMaxSize int, expSize int) {

	if c.maxSize != expMaxSize {
		t.Fatalf(`cache size update from %d to %d not completed correctly. `+
			`Expected max size: %d, got max size: %d`,
			orgMaxSize, expMaxSize, expMaxSize, c.maxSize)
	}

	expNext := expSize
	if expSize == expMaxSize {
		expNext = 0
	}

	if c.nextKey != expNext {
		t.Fatalf(`cache size update from %d to %d not completed correctly. `+
			`Expected next val: %d, got next val: %d`,
			orgMaxSize, expMaxSize, expNext, c.nextKey)
	}

	if c.size != expSize {
		t.Fatalf(`cache size update from %d to %d not completed correctly. `+
			`Expected size val: %d, got size val: %d`,
			orgMaxSize, expMaxSize, expSize, c.size)
	}

	if cap(c.keys) != expMaxSize {
		t.Fatalf(`cache size update from %d to %d not completed correctly. `+
			`Expected cap val: %d, got cap val: %d`,
			orgMaxSize, expMaxSize, expMaxSize, cap(c.keys))
	}

	if len(c.keys) != expMaxSize {
		t.Fatalf(`cache size update from %d to %d not completed correctly. `+
			`Expected len val: %d, got len val: %d`,
			orgMaxSize, expMaxSize, expMaxSize, len(c.keys))
	}
}
