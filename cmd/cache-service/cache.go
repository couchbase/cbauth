// @author Couchbase <info@couchbase.com>
// @copyright 2016 Couchbase, Inc.
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
package main

import (
	"container/list"
	"errors"
	"sync"
)

const (
	MaxCacheSize = 1024
)

var (
	ErrKeyNotFound = errors.New("Key not found")
)

type item struct {
	key     string
	value   string
	lruElem *list.Element
}

type Cache struct {
	mu    *sync.Mutex
	lru   *list.List
	items map[string]*item

	maxSize int
}

func NewCache() *Cache {
	return &Cache{
		mu:      &sync.Mutex{},
		lru:     list.New(),
		items:   make(map[string]*item),
		maxSize: MaxCacheSize,
	}
}

func (c *Cache) Get(key string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	itm, ok := c.items[key]
	if !ok {
		return "", ErrKeyNotFound
	}

	return itm.value, nil
}

func (c *Cache) Set(key string, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()

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

func (c *Cache) create(key string, value string) {
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
