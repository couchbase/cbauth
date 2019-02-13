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
}

// NewCache creates new Cache
func NewCache(maxSize int) *Cache {
	return &Cache{
		keys:    make([]interface{}, maxSize),
		items:   new(Map),
		nextKey: 0,
		size:    0,
		maxSize: maxSize,
	}
}

// Get gets the value by key, returns (nil, false) if the value is not found
func (c *Cache) Get(key interface{}) (interface{}, bool) {
	return c.items.Load(key)
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
