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
	"container/list"
	"sync"
)

type item struct {
	key     interface{}
	value   interface{}
	lruElem *list.Element
}

// Cache implements simple LRU Cache
type Cache struct {
	sync.Mutex
	lru   *list.List
	items map[interface{}]*item

	maxSize int
}

// NewCache creates new Cache
func NewCache(size int) *Cache {
	return &Cache{
		lru:     list.New(),
		items:   make(map[interface{}]*item),
		maxSize: size,
	}
}

// Get gets the value by key, returns (nil, false) if the value is not found
func (c *Cache) Get(key interface{}) (interface{}, bool) {
	c.Lock()
	defer c.Unlock()

	itm, ok := c.items[key]
	if !ok {
		return nil, false
	}

	c.touch(itm)
	return itm.value, true
}

// Set sets the value for the key in LRU Cache
func (c *Cache) Set(key interface{}, value interface{}) {
	c.Lock()
	defer c.Unlock()

	itm, ok := c.items[key]
	if !ok {
		c.create(key, value)
		return
	}

	itm.value = value
	c.touch(itm)
}

func (c *Cache) maybeEvict() {
	if len(c.items) < c.maxSize {
		return
	}

	victim := c.lru.Remove(c.lru.Front()).(*item)
	delete(c.items, victim.key)
}

func (c *Cache) create(key interface{}, value interface{}) {
	c.maybeEvict()

	itm := &item{
		key:   key,
		value: value,
	}

	itm.lruElem = c.lru.PushBack(itm)

	c.items[key] = itm
}

func (c *Cache) touch(itm *item) {
	c.lru.MoveToBack(itm.lruElem)
}
