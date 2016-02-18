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
	"bytes"
	"fmt"
	"log"
	"os"
	"sync"

	. "github.com/couchbase/cbauth/service_api"
)

type Mgr struct {
	mu      *sync.RWMutex
	waiters waiters

	tokenMapStream *TokenMapStream
	cache          *Cache

	rebalancer   *Rebalancer
	rebalanceCtx *rebalanceContext

	state
}

type rebalanceContext struct {
	change TopologyChange
	rev    uint64
}

type waiter chan state
type waiters map[waiter]struct{}

type state struct {
	rev    uint64
	tokens *TokenMap

	rebalanceId   string
	rebalanceTask *Task
}

func NewMgr() *Mgr {
	mu := &sync.RWMutex{}

	tokenMapStream := NewTokenMapStream()
	tokens := <-tokenMapStream.C

	cache := NewCache()

	mgr := &Mgr{
		mu:             mu,
		waiters:        make(waiters),
		tokenMapStream: tokenMapStream,
		state: state{
			rev:           0,
			tokens:        tokens,
			rebalanceId:   "",
			rebalanceTask: nil,
		},
	}

	go mgr.tokenMapStreamReader()

	httpApi := HttpAPI{mgr, cache}
	go httpApi.ListenAndServe()

	return mgr
}

func RegisterManager() {
	mgr := NewMgr()
	err := RegisterServiceManager(mgr, nil)
	if err != nil {
		log.Fatalf("Couldn't register service manager: %s", err.Error())
	}
}

func (m *Mgr) GetCurrentTokenMap() *TokenMap {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.getCurrentTokenMapLOCKED()
}

func (m *Mgr) getCurrentTokenMapLOCKED() *TokenMap {
	return m.copyStateLOCKED().tokens
}

func (m *Mgr) GetNodeInfo() (*NodeInfo, error) {
	opaque := struct {
		Host string `json:"host"`
	}{
		MyHost,
	}

	info := &NodeInfo{
		NodeId:   MyNode,
		Priority: 0,
		Opaque:   opaque,
	}

	return info, nil
}

func (m *Mgr) Shutdown() error {
	os.Exit(0)

	return nil
}

func (m *Mgr) GetTaskList(rev Revision, cancel Cancel) (*TaskList, error) {
	state, err := m.wait(rev, cancel)
	if err != nil {
		return nil, err
	}

	return stateToTaskList(state), nil
}

func (m *Mgr) CancelTask(id string, rev Revision) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	tasks := stateToTaskList(m.state).Tasks
	task := (*Task)(nil)

	for i := range tasks {
		t := &tasks[i]

		if t.Id == id {
			task = t
			break
		}
	}

	if task == nil {
		return ErrNotFound
	}

	if !task.IsCancelable {
		return ErrNotSupported
	}

	if rev != nil && !bytes.Equal(rev, task.Rev) {
		return ErrConflict
	}

	return m.cancelActualTaskLOCKED(task)
}

func (m *Mgr) GetCurrentTopology(rev Revision, cancel Cancel) (*Topology, error) {
	state, err := m.wait(rev, cancel)
	if err != nil {
		return nil, err
	}

	return stateToTopology(state), nil
}

func (m *Mgr) PrepareTopologyChange(change TopologyChange) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.state.rebalanceId != "" {
		return ErrConflict
	}

	m.updateStateLOCKED(func(s *state) {
		s.rebalanceId = change.Id
	})

	return nil
}

func (m *Mgr) StartTopologyChange(change TopologyChange) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.state.rebalanceId != change.Id || m.rebalancer != nil {
		return ErrConflict
	}

	if change.CurrentTopologyRev != nil {
		haveRev := DecodeRev(change.CurrentTopologyRev)
		if haveRev != m.state.rev {
			return ErrConflict
		}
	}

	ctx := &rebalanceContext{
		rev:    0,
		change: change,
	}

	tokens := m.getCurrentTokenMapLOCKED()
	rebalancer := NewRebalancer(tokens, change,
		m.rebalanceProgressCallback, m.rebalanceDoneCallback)

	m.rebalancer = rebalancer
	m.rebalanceCtx = ctx

	return nil
}

func (m *Mgr) runRebalanceCallback(cancel <-chan struct{}, body func()) {
	done := make(chan struct{})

	go func() {
		m.mu.Lock()
		defer m.mu.Unlock()

		select {
		case <-cancel:
			break
		default:
			body()
		}

		close(done)
	}()

	select {
	case <-done:
	case <-cancel:
	}
}

func (m *Mgr) rebalanceProgressCallback(rev uint64, progress float64, cancel <-chan struct{}) {
	m.runRebalanceCallback(cancel, func() {
		m.rebalanceCtx.rev = rev

		changeId := m.rebalanceCtx.change.Id
		task := &Task{
			Rev:          EncodeRev(rev),
			Id:           fmt.Sprintf("rebalance/%s", changeId),
			Type:         TaskTypeRebalance,
			Status:       TaskStatusRunning,
			IsCancelable: true,
			Progress:     progress,

			Extra: map[string]interface{}{
				"rebalanceId": changeId,
			},
		}

		m.updateStateLOCKED(func(s *state) {
			s.rebalanceTask = task
		})
	})
}

func (m *Mgr) rebalanceDoneCallback(err error, cancel <-chan struct{}) {
	m.runRebalanceCallback(cancel, func() { m.onRebalanceDoneLOCKED(err) })
}

func (m *Mgr) onRebalanceDoneLOCKED(err error) {
	newTask := (*Task)(nil)
	if err != nil {
		ctx := m.rebalanceCtx

		newTask = &Task{
			Rev:          EncodeRev(ctx.rev),
			Id:           fmt.Sprintf("rebalance/%s", ctx.change.Id),
			Type:         TaskTypeRebalance,
			Status:       TaskStatusFailed,
			IsCancelable: true,

			ErrorMessage: err.Error(),

			Extra: map[string]interface{}{
				"rebalanceId": ctx.change.Id,
			},
		}
	}

	m.rebalancer = nil
	m.rebalanceCtx = nil

	m.updateStateLOCKED(func(s *state) {
		s.rebalanceTask = newTask
		s.rebalanceId = ""
	})
}

func (m *Mgr) notifyWaitersLOCKED() {
	s := m.copyStateLOCKED()
	for ch := range m.waiters {
		if ch != nil {
			ch <- s
		}
	}

	m.waiters = make(waiters)
}

func (m *Mgr) addWaiterLOCKED() waiter {
	ch := make(waiter, 1)
	m.waiters[ch] = struct{}{}

	return ch
}

func (m *Mgr) removeWaiter(w waiter) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.waiters, w)
}

func (m *Mgr) tokenMapStreamReader() {
	for {
		select {
		case tokens := <-m.tokenMapStream.C:
			if m.tokenMapStream.IsCanceled() {
				return
			}

			m.updateState(func(s *state) {
				s.tokens = tokens
			})
		}
	}
}

func (m *Mgr) updateState(body func(state *state)) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.updateStateLOCKED(body)
}

func (m *Mgr) updateStateLOCKED(body func(state *state)) {
	body(&m.state)
	m.state.rev += 1

	m.notifyWaitersLOCKED()
}

func (m *Mgr) wait(rev Revision, cancel Cancel) (state, error) {
	m.mu.Lock()

	unlock := NewCleanup(func() { m.mu.Unlock() })
	defer unlock.Run()

	currState := m.copyStateLOCKED()

	if rev == nil {
		return currState, nil
	}

	haveRev := DecodeRev(rev)
	if haveRev != m.rev {
		return currState, nil
	}

	ch := m.addWaiterLOCKED()
	unlock.Run()

	select {
	case <-cancel:
		m.removeWaiter(ch)
		return state{}, ErrCanceled
	case newState := <-ch:
		return newState, nil
	}
}

func (m *Mgr) copyStateLOCKED() state {
	s := m.state
	s.tokens = s.tokens.Copy()

	return s
}

func (m *Mgr) cancelActualTaskLOCKED(task *Task) error {
	switch task.Type {
	case TaskTypePrepared:
		return m.cancelPrepareTaskLOCKED()
	case TaskTypeRebalance:
		return m.cancelRebalanceTaskLOCKED(task)
	default:
		panic("can't happen")
	}
}

func (m *Mgr) cancelPrepareTaskLOCKED() error {
	if m.rebalancer != nil {
		return ErrConflict
	}

	m.updateStateLOCKED(func(s *state) {
		s.rebalanceId = ""
	})

	return nil
}

func (m *Mgr) cancelRebalanceTaskLOCKED(task *Task) error {
	switch task.Status {
	case TaskStatusRunning:
		return m.cancelRunningRebalanceTaskLOCKED()
	case TaskStatusFailed:
		return m.cancelFailedRebalanceTaskLOCKED()
	default:
		panic("can't happen")
	}
}

func (m *Mgr) cancelRunningRebalanceTaskLOCKED() error {
	m.rebalancer.Cancel()
	m.onRebalanceDoneLOCKED(nil)

	return nil
}

func (m *Mgr) cancelFailedRebalanceTaskLOCKED() error {
	m.updateStateLOCKED(func(s *state) {
		s.rebalanceTask = nil
	})

	return nil
}

func stateToTopology(s state) *Topology {
	topology := &Topology{}

	topology.Rev = EncodeRev(s.rev)
	topology.Nodes = s.tokens.Servers
	topology.IsBalanced = true
	topology.Messages = nil

	return topology
}

func stateToTaskList(s state) *TaskList {
	tasks := &TaskList{}

	tasks.Rev = EncodeRev(s.rev)
	tasks.Tasks = make([]Task, 0)

	if s.rebalanceId != "" {
		id := s.rebalanceId

		task := Task{
			Rev:          EncodeRev(0),
			Id:           fmt.Sprintf("prepare/%s", id),
			Type:         TaskTypePrepared,
			Status:       TaskStatusRunning,
			IsCancelable: true,

			Extra: map[string]interface{}{
				"rebalanceId": id,
			},
		}

		tasks.Tasks = append(tasks.Tasks, task)
	}

	if s.rebalanceTask != nil {
		tasks.Tasks = append(tasks.Tasks, *s.rebalanceTask)
	}

	return tasks
}
