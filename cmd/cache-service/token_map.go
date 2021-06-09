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
	"encoding/json"
	"hash/crc32"
	"math/rand"
	"sort"

	"github.com/couchbase/cbauth/metakv"
	"github.com/couchbase/cbauth/service"
	log "github.com/couchbase/clog"
)

const (
	TokensPerNode = 256

	ServiceDir = "/cache-service/"
	TokensKey  = ServiceDir + "tokens"
)

type Token struct {
	Point  uint32
	Server service.NodeID
}

type TokenList []Token

func (tl TokenList) Len() int {
	return len(tl)
}

func (tl TokenList) Less(i, j int) bool {
	return tl[i].Point < tl[j].Point
}

func (tl TokenList) Swap(i, j int) {
	tl[i], tl[j] = tl[j], tl[i]
}

type TokenMap struct {
	Servers []service.NodeID
	Tokens  TokenList
}

func (tm TokenMap) save() {
	MetakvSet(TokensKey, tm)
}

func MaybeCreateInitialTokenMap() {
	tm := &TokenMap{}
	if MetakvGet(TokensKey, tm) {
		return
	}

	log.Printf("No token map found. Creating initial one.")

	tm.Servers = []service.NodeID{}
	tm.Tokens = TokenList{}

	tm.save()
}

func (tm TokenMap) UpdateServers(newServers []service.NodeID) {
	removed := serversMap(tm.Servers)
	added := serversMap(newServers)

	for _, newServer := range newServers {
		delete(removed, newServer)
	}

	for _, oldServer := range tm.Servers {
		delete(added, oldServer)
	}

	newTokens := TokenList(nil)
	for _, token := range tm.Tokens {
		if _, ok := removed[token.Server]; ok {
			continue
		}

		newTokens = append(newTokens, token)
	}

	for addedServer := range added {
		newTokens = append(newTokens, createTokens(addedServer)...)
	}

	tm.Servers = append([]service.NodeID{}, newServers...)
	tm.Tokens = newTokens

	sort.Sort(tm.Tokens)
	tm.save()
}

func (tm TokenMap) FindOwner(key string) service.NodeID {
	h := hash(key)

	numTokens := len(tm.Tokens)
	i := sort.Search(numTokens,
		func(i int) bool {
			return tm.Tokens[i].Point > h
		})

	if i >= numTokens {
		i = 0
	}

	return tm.Tokens[i].Server
}

func (tm TokenMap) Copy() *TokenMap {
	cp := &TokenMap{}

	cp.Servers = append([]service.NodeID{}, tm.Servers...)
	cp.Tokens = append(TokenList{}, tm.Tokens...)

	return cp
}

func hash(key string) uint32 {
	return crc32.ChecksumIEEE([]byte(key))
}

func createTokens(node service.NodeID) TokenList {
	tokens := TokenList(nil)

	for i := 0; i < TokensPerNode; i++ {
		tokens = append(tokens, Token{rand.Uint32(), node})
	}

	return tokens
}

func serversMap(servers []service.NodeID) map[service.NodeID]struct{} {
	m := make(map[service.NodeID]struct{})

	for _, server := range servers {
		m[server] = struct{}{}
	}

	return m
}

type TokenMapStream struct {
	C      <-chan *TokenMap
	cancel chan struct{}
}

func NewTokenMapStream() *TokenMapStream {
	cancel := make(chan struct{})
	ch := make(chan *TokenMap)

	cb := func(kve metakv.KVEntry) error {
		if kve.Path != TokensKey {
			return nil
		}

		tokens := &TokenMap{}
		err := json.Unmarshal(kve.Value, tokens)
		if err != nil {
			log.Fatalf("Failed to unmarshal token map: %s\n%s",
				err.Error(), string(kve.Value))
		}

		select {
		case ch <- tokens:
		case <-cancel:
		}

		return nil
	}

	go metakv.RunObserveChildrenV2(ServiceDir, cb, cancel)

	return &TokenMapStream{
		C:      ch,
		cancel: cancel,
	}
}

func (s *TokenMapStream) IsCanceled() bool {
	select {
	case <-s.cancel:
		return true
	default:
		return false
	}
}

func (s *TokenMapStream) Cancel() {
	close(s.cancel)
}
