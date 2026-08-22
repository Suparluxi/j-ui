package api

import (
	"database/sql"
	"errors"
	"sync"
	"time"

	"github.com/Suparluxi/j-ui/internal/database"
	"github.com/Suparluxi/j-ui/internal/model"
	"github.com/Suparluxi/j-ui/internal/problem"
	"github.com/Suparluxi/j-ui/internal/secure"
)

const (
	residentialJobQueued    = "queued"
	residentialJobRunning   = "running"
	residentialJobSucceeded = "succeeded"
	residentialJobFailed    = "failed"
)

type residentialJob struct {
	ID         string      `json:"id"`
	Status     string      `json:"status"`
	Message    string      `json:"message"`
	CreatedAt  time.Time   `json:"createdAt"`
	UpdatedAt  time.Time   `json:"updatedAt"`
	Node       *model.Node `json:"node,omitempty"`
	URI        string      `json:"uri,omitempty"`
	Source     string      `json:"source,omitempty"`
	Country    string      `json:"country,omitempty"`
	ExitID     int64       `json:"exitId,omitempty"`
	ReusedExit bool        `json:"reusedExit,omitempty"`
	ExpiresAt  *time.Time  `json:"expiresAt,omitempty"`
	Error      *apiError   `json:"error,omitempty"`
}

type residentialJobManager struct {
	mu   sync.RWMutex
	jobs map[string]*residentialJob
}

func newResidentialJobManager() *residentialJobManager {
	return &residentialJobManager{jobs: make(map[string]*residentialJob)}
}

func (m *residentialJobManager) create(source string) (residentialJob, error) {
	id, err := secure.RandomToken(18)
	if err != nil {
		return residentialJob{}, err
	}
	now := time.Now().UTC()
	job := &residentialJob{
		ID: id, Status: residentialJobQueued,
		Message: "住宅节点创建任务已排队", Source: source,
		CreatedAt: now, UpdatedAt: now,
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked(now)
	m.jobs[id] = job
	return cloneResidentialJob(*job), nil
}

func (m *residentialJobManager) start(id string) {
	m.update(id, func(job *residentialJob) {
		job.Status = residentialJobRunning
		job.Message = "正在创建 VPNGate 隧道、节点并检查配置"
		job.Error = nil
	})
}

func (m *residentialJobManager) complete(id string, result residentialJobResult) {
	m.update(id, func(job *residentialJob) {
		job.Status = residentialJobSucceeded
		job.Message = "住宅节点创建完成"
		job.Node = &result.Node
		job.URI = result.URI
		job.Source = result.Source
		job.Country = result.Country
		job.ExitID = result.ExitID
		job.ReusedExit = result.ReusedExit
		job.ExpiresAt = result.ExpiresAt
		job.Error = nil
	})
}

func (m *residentialJobManager) fail(id string, err error) {
	value := publicAPIError(err)
	m.update(id, func(job *residentialJob) {
		job.Status = residentialJobFailed
		job.Message = "住宅节点创建失败"
		job.Error = &value
	})
}

func (m *residentialJobManager) get(id string) (residentialJob, bool) {
	m.mu.RLock()
	job, ok := m.jobs[id]
	if !ok {
		m.mu.RUnlock()
		return residentialJob{}, false
	}
	copy := cloneResidentialJob(*job)
	m.mu.RUnlock()
	return copy, true
}

func (m *residentialJobManager) update(id string, update func(*residentialJob)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	job, ok := m.jobs[id]
	if !ok {
		return
	}
	update(job)
	job.UpdatedAt = time.Now().UTC()
}

func (m *residentialJobManager) pruneLocked(now time.Time) {
	for id, job := range m.jobs {
		if (job.Status == residentialJobSucceeded || job.Status == residentialJobFailed) &&
			now.Sub(job.UpdatedAt) > 30*time.Minute {
			delete(m.jobs, id)
		}
	}
}

type residentialJobResult struct {
	Node       model.Node
	URI        string
	Source     string
	Country    string
	ExitID     int64
	ReusedExit bool
	ExpiresAt  *time.Time
}

func cloneResidentialJob(job residentialJob) residentialJob {
	if job.Node != nil {
		node := *job.Node
		job.Node = &node
	}
	if job.Error != nil {
		value := *job.Error
		job.Error = &value
	}
	return job
}

func publicAPIError(err error) apiError {
	if value, ok := problem.As(err); ok {
		return apiError{Code: value.Code, Message: value.Message}
	}
	if database.IsConflict(err) {
		return apiError{Code: "resource_conflict", Message: "资源冲突"}
	}
	if database.IsNotFound(err) || errors.Is(err, sql.ErrNoRows) {
		return apiError{Code: "not_found", Message: "资源不存在"}
	}
	return apiError{Code: "internal_error", Message: "服务器内部错误"}
}
