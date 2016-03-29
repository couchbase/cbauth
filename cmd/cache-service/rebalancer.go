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
	"time"

	"github.com/couchbase/cbauth/service"
)

type DoneCallback func(err error, cancel <-chan struct{})
type ProgressCallback func(progress float64, cancel <-chan struct{})

type Callbacks struct {
	progress ProgressCallback
	done     DoneCallback
}

type Rebalancer struct {
	tokens *TokenMap
	change service.TopologyChange

	cb Callbacks

	cancel chan struct{}
	done   chan struct{}
}

func NewRebalancer(tokens *TokenMap, change service.TopologyChange,
	progress ProgressCallback, done DoneCallback) *Rebalancer {

	r := &Rebalancer{
		tokens: tokens,
		change: change,
		cb:     Callbacks{progress, done},

		cancel: make(chan struct{}),
		done:   make(chan struct{}),
	}

	go r.doRebalance()
	return r
}

func (r *Rebalancer) Cancel() {
	close(r.cancel)
	<-r.done
}

func (r *Rebalancer) doRebalance() {
	defer close(r.done)

	isInitial := (len(r.tokens.Servers) == 0)
	isFailover := (r.change.Type == service.TopologyChangeTypeFailover)

	if !(isFailover || isInitial) {
		// make failover and initial rebalance fast
		r.fakeProgress()
	}

	r.updateHostNames()
	r.updateTokenMap()
	r.cb.done(nil, r.cancel)
}

func (r *Rebalancer) fakeProgress() {
	seconds := 20
	progress := float64(0)
	increment := 1.0 / float64(seconds)

	r.cb.progress(progress, r.cancel)

	for i := 0; i < seconds; i++ {
		select {
		case <-time.After(1 * time.Second):
			progress += increment
			r.cb.progress(progress, r.cancel)
		case <-r.cancel:
			return
		}
	}
}

func (r *Rebalancer) updateHostNames() {
	for _, node := range r.change.KeepNodes {
		id := node.NodeInfo.NodeID
		opaque := node.NodeInfo.Opaque.(map[string]interface{})
		host := opaque["host"].(string)

		SetNodeHostName(id, host)
	}
}

func (r *Rebalancer) updateTokenMap() {
	nodes := []service.NodeID(nil)

	for _, node := range r.change.KeepNodes {
		nodes = append(nodes, node.NodeInfo.NodeID)
	}

	r.tokens.UpdateServers(nodes)
}
