// @author Couchbase <info@couchbase.com>
// @copyright 2015 Couchbase, Inc.
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
package service

import (
	"errors"
	"net/rpc"
	"strings"
	"sync"
	"time"

	"github.com/couchbase/cbauth/revrpc"
)

type serviceAPI struct {
	mgr                 Manager
	autofailoverManager AutofailoverManager
	serverlessManager   ServerlessManager
	hibernationManager  HibernationManager
	infoManager         InfoManager
	bucketConfigManager BucketConfigurationManager
}

type Void *struct{}

func withTimeout(timeout int64, body func(Cancel)) {
	cancel := make(chan struct{})
	once := &sync.Once{}

	if timeout != 0 {
		go func() {
			timer := time.After(time.Duration(timeout) * time.Millisecond)
			select {
			case <-timer:
				once.Do(func() { close(cancel) })
			case <-cancel:
			}
		}()
	}

	body(cancel)
	once.Do(func() { close(cancel) })
}

func (s serviceAPI) GetNodeInfo(Void, res *NodeInfo) error {
	info, err := s.mgr.GetNodeInfo()
	if err != nil {
		return err
	}

	*res = *info
	return nil
}

type GetCurrentTopologyReq struct {
	Rev     Revision `json:"rev,omitempty"`
	Timeout int64    `json:"timeout,omitempty"`
}

func (s serviceAPI) Shutdown(Void, res *Void) error {
	*res = nil

	return s.mgr.Shutdown()
}

func (s serviceAPI) GetCurrentTopology(req GetCurrentTopologyReq, res *Topology) error {
	var topology *Topology
	var err error

	withTimeout(req.Timeout, func(cancel Cancel) {
		topology, err = s.mgr.GetCurrentTopology(req.Rev, cancel)
		if err == ErrCanceled {
			topology, err = s.mgr.GetCurrentTopology(nil, nil)
		}
	})

	if err == nil {
		*res = *topology
	}

	return err
}

type GetTaskListReq struct {
	Rev     Revision `json:"rev,omitempty"`
	Timeout int64    `json:"timeout,omitempty"`
}

func (s serviceAPI) GetTaskList(req GetTaskListReq, res *TaskList) error {
	var tasks *TaskList
	var err error

	withTimeout(req.Timeout, func(cancel Cancel) {
		tasks, err = s.mgr.GetTaskList(req.Rev, cancel)
		if err == ErrCanceled {
			tasks, err = s.mgr.GetTaskList(nil, nil)
		}
	})

	if err == nil {
		*res = *tasks
	}

	return err
}

type CancelTaskReq struct {
	ID  string   `json:"id"`
	Rev Revision `json:"rev,omitempty"`
}

func (s serviceAPI) CancelTask(req CancelTaskReq, res *Void) error {
	*res = nil

	return s.mgr.CancelTask(req.ID, req.Rev)
}

func (s serviceAPI) PrepareTopologyChange(req TopologyChange, res *Void) error {
	*res = nil

	return s.mgr.PrepareTopologyChange(req)
}

func (s serviceAPI) StartTopologyChange(req TopologyChange, res *Void) error {
	*res = nil

	return s.mgr.StartTopologyChange(req)
}

func (s serviceAPI) GetParams(Void, res *map[string]interface{}) error {
	if s.infoManager == nil {
		// it's allowed not to implement this
		*res = map[string]interface{}{}
		return nil
	}

	params := s.infoManager.GetParams()
	*res = *params
	return nil
}

func (s serviceAPI) HealthCheck(Void, res *HealthInfo) error {
	if s.autofailoverManager == nil {
		return errors.New("AutofailoverManager is not implemented")
	}

	info, err := s.autofailoverManager.HealthCheck()
	if err != nil {
		return err
	}

	*res = *info
	return nil
}

func (s serviceAPI) IsSafe(nodeIds []NodeID, res *Void) error {
	*res = nil

	if s.autofailoverManager == nil {
		return errors.New("AutofailoverManager is not implemented")
	}

	return s.autofailoverManager.IsSafe(nodeIds)
}

// For some strange reason golang jsonrpc doesn't allow to return
// any marshallable type except struct. So we have to wrap map returned
// by the service into structure to deal with this peculiarity.
type DefragmentedUtilizationReply struct {
	Info *DefragmentedUtilizationInfo
}

func (s serviceAPI) GetDefragmentedUtilization(Void,
	res *DefragmentedUtilizationReply) error {

	if s.serverlessManager == nil {
		return errors.New("ServerlessManager is not implemented")
	}

	info, err := s.serverlessManager.GetDefragmentedUtilization()
	if err != nil {
		return err
	}

	res.Info = info
	return nil
}

func (s serviceAPI) Pause(params PauseParams, res *Void) error {
	*res = nil

	if s.hibernationManager == nil {
		return errors.New("HibernationManager is not implemented")
	}
	return s.hibernationManager.Pause(params)
}

func (s serviceAPI) PreparePause(params PauseParams, res *Void) error {
	*res = nil

	if s.hibernationManager == nil {
		return errors.New("HibernationManager is not implemented")
	}
	return s.hibernationManager.PreparePause(params)
}

func (s serviceAPI) PrepareResume(params ResumeParams, res *Void) error {
	*res = nil

	if s.hibernationManager == nil {
		return errors.New("HibernationManager is not implemented")
	}
	return s.hibernationManager.PrepareResume(params)
}

func (s serviceAPI) Resume(params ResumeParams, res *Void) error {
	*res = nil

	if s.hibernationManager == nil {
		return errors.New("HibernationManager is not implemented")
	}
	return s.hibernationManager.Resume(params)
}

// trimRightUntil trims contiguous runes in 'cutset' from the right of 's' stopping if 's' drops below 'n' runes long.
func trimRightUntil(s []rune, cutset []rune, n int) []rune {
	inCutset := func(c rune) bool {
		for _, cut := range cutset {
			if c == cut {
				return true
			}
		}

		return false
	}

	for len(s) > 0 && len(s) > n {
		if !inCutset(s[len(s)-1]) {
			break
		}

		s = s[0 : len(s)-1]
	}

	return s
}

// takeUntil grabs characters until it finds an unescaped 'separator'. The return value is stripped of (unescaped)
// spaces.
func takeUntil(src string, separator rune) (string, string) {
	const whitespace = "\r\n\t "

	src = strings.TrimLeft(src, whitespace)

	var (
		runes  = []rune(src)
		escape = false
		res    = make([]rune, 0, len(src))

		i           int
		lastEscaped int
	)

	for i = 0; i < len(src); i++ {
		char := runes[i]
		if !escape && char == separator {
			break
		}

		if char == '\\' {
			lastEscaped = len(res) + 1
			escape = true
		} else {
			res = append(res, char)
			escape = false
		}
	}

	s := string(trimRightUntil(res, []rune(whitespace), lastEscaped))
	if i >= len(src)-1 {
		return s, ""
	}

	return s, string([]rune(src)[i+1:])
}

func parseConfig(cfg string) map[string]string {
	res := make(map[string]string, 0)

	for len(cfg) > 0 {
		var key, value string
		key, cfg = takeUntil(cfg, '=')
		value, cfg = takeUntil(cfg, ';')
		res[key] = value
	}

	return res
}

func (s serviceAPI) ValidateBucketConfig(params BucketConfigParams, res *BucketValidationResult) error {
	var result *BucketValidationResult
	var err error

	if s.bucketConfigManager == nil {
		return errors.New("BucketConfigurationManager is not implemented")
	}

	cfg := parseConfig(params.Config)

	result, err = s.bucketConfigManager.ValidateBucketConfig(cfg)
	if err == nil {
		*res = *result
	}

	return err
}

func RegisterManager(mgr Manager, errorPolicy revrpc.BabysitErrorPolicy) error {

	service, err := revrpc.GetDefaultServiceFromEnv("service_api")
	if err != nil {
		return err
	}

	autofailoverManager, _ := mgr.(AutofailoverManager)
	serverlessManager, _ := mgr.(ServerlessManager)
	hibernationManager, _ := mgr.(HibernationManager)
	infoManager, _ := mgr.(InfoManager)
	bucketConfigManager, _ := mgr.(BucketConfigurationManager)

	setup := func(rpc *rpc.Server) error {
		return rpc.RegisterName("ServiceAPI",
			&serviceAPI{mgr, autofailoverManager, serverlessManager,
				hibernationManager, infoManager, bucketConfigManager})
	}

	return revrpc.BabysitService(setup, service, errorPolicy)
}
