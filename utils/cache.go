// @author Couchbase <info@couchbase.com>
// @copyright 2017-2019 Couchbase, Inc.
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
	"sync"
	"sync/atomic"
)

// Cache implements simple cache optimized for concurrent reads. Items are
// evicted in the order of their creation.
type Cache struct {
	sync.Mutex

	// Keys currently stored in the cache. Keys are added to the slice in
	// the order of their creation wrapping around when maxSize is
	// reached.
	keys  []interface{}
	items *Map

	// Points to the position in the keys slice above where the next
	// created key will get stored.
	nextKey int

	size    int
	maxSize int

	hitCnt  uint64
	missCnt uint64
}

// NewCache creates new Cache
func NewCache(maxSize int) *Cache {
	return &Cache{
		keys:    make([]interface{}, maxSize),
		items:   new(Map),
		nextKey: 0,
		size:    0,
		maxSize: maxSize,
		hitCnt:  0,
		missCnt: 0,
	}
}

// Get gets the value by key, returns (nil, false) if the value is not found.
// It also updates Hit/Miss counts
func (c *Cache) Get(key interface{}) (interface{}, bool) {
	v, found := c.items.Load(key)
	if found {
		atomic.AddUint64(&c.hitCnt, 1)
	} else {
		atomic.AddUint64(&c.missCnt, 1)
	}
	return v, found
}

// Add adds a key/value mapping to the cache if it doesn't already
// exist. Returns true if the mapping was added and false otherwise.
func (c *Cache) Add(key interface{}, value interface{}) bool {
	c.Lock()
	defer c.Unlock()

	_, loaded := c.items.LoadOrStore(key, value)
	if loaded {
		return false
	}

	if c.size < c.maxSize {
		c.size++
	} else {
		victim := c.keys[c.nextKey]
		c.items.Delete(victim)
	}

	c.keys[c.nextKey] = key
	c.nextKey = (c.nextKey + 1) % c.maxSize

	return true
}

// UpdateSize updates the cache size. This function takes care of fragmentation
// in keys after the update is done. Returns true if the cache size is updated
// otherwise it returns false.
func (c *Cache) UpdateSize(newMaxSize int) bool {
	if newMaxSize == c.maxSize || newMaxSize < 1 {
		return false
	}
	c.Lock()
	defer c.Unlock()
	updateSizeLocked(c, newMaxSize)

	return true
}

func updateSizeLocked(c *Cache, newMaxSize int) {
	if newMaxSize > c.maxSize {
		increaseCacheSize(c, newMaxSize)
	} else {
		decreaseCacheSize(c, newMaxSize)
	}
}

func increaseCacheSize(c *Cache, newMaxSize int) {
	newKeysTemp := make([]interface{}, newMaxSize)
	if c.size < c.maxSize { // not rotated
		copy(newKeysTemp, c.keys)
	} else {
		copySegmented(newKeysTemp, c, c.nextKey)
	}
	c.keys = newKeysTemp
	c.nextKey = c.size
	c.maxSize = newMaxSize
}

func decreaseCacheSize(c *Cache, newMaxSize int) {
	newKeysTemp := make([]interface{}, newMaxSize)
	if c.size < c.maxSize { // not rotated
		currentStart, _ := deleteItems(c, 0, newMaxSize)
		copy(newKeysTemp, c.keys[currentStart:c.nextKey])
	} else { // rotated
		currentStart, deletionRotated := deleteItems(c, c.nextKey, newMaxSize)
		if deletionRotated {
			copy(newKeysTemp, c.keys[currentStart:c.nextKey])
		} else {
			copySegmented(newKeysTemp, c, currentStart)
		}
	}
	c.keys = newKeysTemp
	c.nextKey = c.size % newMaxSize
	c.maxSize = newMaxSize
}

func copySegmented(dest []interface{}, c *Cache, segRightStart int) {
	rightSegItmCnt := copy(dest, c.keys[segRightStart:])
	tail := dest[rightSegItmCnt:]
	copy(tail, c.keys[:c.nextKey])
}

func deleteItems(c *Cache, delStart int, desiredSize int) (int, bool) {
	deletionRotated := false
	curr := delStart
	for c.size > desiredSize {
		victim := c.keys[curr]
		c.items.Delete(victim)
		curr = (curr + 1) % c.maxSize
		if curr == 0 {
			deletionRotated = true
		}
		c.size--
	}
	return curr, deletionRotated
}

// GetHitMiss returns Hit/Miss counts
func (c *Cache) GetStats() (int, int, uint64, uint64) {
	return c.maxSize, c.size, c.hitCnt, c.missCnt
}
