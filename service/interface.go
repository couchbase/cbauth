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
)

var (
	ErrNotFound           = errors.New("not_found")
	ErrConflict           = errors.New("conflict")
	ErrNotSupported       = errors.New("operation_not_supported")
	ErrCanceled           = errors.New("operation_canceled")
	ErrRecoveryImpossible = errors.New("recovery_impossible")
)

type Revision []byte
type Priority int64
type NodeID string

type NodeInfo struct {
	NodeID   NodeID      `json:"nodeId"`
	Priority Priority    `json:"priority"`
	Opaque   interface{} `json:"opaque"`
}

type Topology struct {
	Rev   Revision `json:"rev"`
	Nodes []NodeID `json:"nodes"`

	IsBalanced bool     `json:"isBalanced"`
	Messages   []string `json:"messages,omitempty"`
}

type TaskType string

const (
	TaskTypeRebalance    = TaskType("task-rebalance")
	TaskTypePrepared     = TaskType("task-prepared")
	TaskTypeBucketPause  = TaskType("task-pause-bucket")
	TaskTypeBucketResume = TaskType("task-resume-bucket")
)

type TaskStatus string

const (
	TaskStatusRunning = TaskStatus("task-running")
	TaskStatusFailed  = TaskStatus("task-failed")

	// TaskStatusCannotResume is a special task status used only during the
	// dry_run phase for "resuming a bucket".

	TaskStatusCannotResume = TaskStatus("task-status-cannot-resume")
)

type Task struct {
	Rev Revision `json:"rev"`

	ID           string     `json:"id"`
	Type         TaskType   `json:"type"`
	Status       TaskStatus `json:"status"`
	IsCancelable bool       `json:"isCancelable"`

	Progress         float64            `json:"progress"`
	DetailedProgress map[NodeID]float64 `json:"detailedProgress,omitempty"`

	Description  string `json:"description,omitempty"`
	ErrorMessage string `json:"errorMessage,omitempty"`

	Extra map[string]interface{} `json:"extra"`
}

type TaskList struct {
	Rev   Revision `json:"rev"`
	Tasks []Task   `json:"tasks"`
}

type Cancel <-chan struct{}

type RecoveryType string

const (
	RecoveryTypeFull  = RecoveryType("recovery-full")
	RecoveryTypeDelta = RecoveryType("recovery-delta")
)

type TopologyChangeType string

const (
	TopologyChangeTypeRebalance = TopologyChangeType("topology-change-rebalance")
	TopologyChangeTypeFailover  = TopologyChangeType("topology-change-failover")
)

type TopologyChange struct {
	ID                 string   `json:"id"`
	CurrentTopologyRev Revision `json:"currentTopologyRev"`

	Type TopologyChangeType `json:"type"`

	KeepNodes []struct {
		NodeInfo     NodeInfo     `json:"nodeInfo"`
		RecoveryType RecoveryType `json:"recoveryType"`
	} `json:"keepNodes"`

	EjectNodes []NodeInfo `json:"ejectNodes"`
}

type HealthInfo struct {
	// number of the disk failures encountered since the
	// start of the service executable
	DiskFailures int `json:"diskFailures"`
}

type Manager interface {
	GetNodeInfo() (*NodeInfo, error)
	Shutdown() error

	GetTaskList(rev Revision, cancel Cancel) (*TaskList, error)
	CancelTask(id string, rev Revision) error

	GetCurrentTopology(rev Revision, cancel Cancel) (*Topology, error)

	PrepareTopologyChange(change TopologyChange) error
	StartTopologyChange(change TopologyChange) error
}

type InfoManager interface {
	GetParams() *map[string]interface{}
}

type AutofailoverManager interface {
	// returns HealthInfo if the service considers itself overall
	// healthy and error otherwise
	HealthCheck() (*HealthInfo, error)
	// returns nil if the auto failover is safe from the service
	// perspective for the NodeID's passed, and error otherwise
	IsSafe(nodeUUIDs []NodeID) error
}

type DefragmentedUtilizationInfo map[string]map[string]interface{}

type ServerlessManager interface {
	// returns projected utilization stats if the service would
	// be defragmented
	GetDefragmentedUtilization() (*DefragmentedUtilizationInfo, error)
}

type PauseParams struct {
	ID                string `json:"id"`
	Bucket            string `json:"bucket"`
	RemotePath        string `json:"remotePath"`
	BlobStorageRegion string `json:"blobStorageRegion"`
	RateLimit         uint64 `json:"rateLimit"`
}

type ResumeParams struct {
	ID                string `json:"id"`
	Bucket            string `json:"bucket"`
	RemotePath        string `json:"remotePath"`
	BlobStorageRegion string `json:"blobStorageRegion"`
	DryRun            bool   `json:"dryRun"`
	RateLimit         uint64 `json:"rateLimit"`
}

type HibernationManager interface {
	PreparePause(params PauseParams) error
	Pause(params PauseParams) error

	PrepareResume(params ResumeParams) error
	Resume(params ResumeParams) error
}
