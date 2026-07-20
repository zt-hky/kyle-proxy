package telegram

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type AccessStatus string

const (
	AccessPending  AccessStatus = "pending"
	AccessApproved AccessStatus = "approved"
	AccessDenied   AccessStatus = "denied"
)

type AccessRecord struct {
	UserID      int64        `json:"user_id"`
	ChatID      int64        `json:"chat_id"`
	Username    string       `json:"username,omitempty"`
	DisplayName string       `json:"display_name"`
	Status      AccessStatus `json:"status"`
	RequestedAt time.Time    `json:"requested_at"`
	DecidedAt   *time.Time   `json:"decided_at,omitempty"`
}

type accessFile struct {
	Users []AccessRecord `json:"users"`
}
type AccessStore struct {
	mu      sync.Mutex
	path    string
	ownerID int64
	users   map[int64]AccessRecord
}

func NewAccessStore(path string, ownerID int64) (*AccessStore, error) {
	s := &AccessStore{path: path, ownerID: ownerID, users: make(map[int64]AccessRecord)}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read access store: %w", err)
	}
	var file accessFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("decode access store: %w", err)
	}
	now := time.Now()
	for _, rec := range file.Users {
		if rec.UserID <= 0 || rec.ChatID <= 0 || rec.ChatID != rec.UserID || rec.UserID == ownerID {
			return nil, fmt.Errorf("invalid access record")
		}
		if rec.Status != AccessPending && rec.Status != AccessApproved && rec.Status != AccessDenied {
			return nil, fmt.Errorf("invalid access status")
		}
		if rec.RequestedAt.IsZero() || rec.RequestedAt.After(now.Add(time.Minute)) {
			return nil, fmt.Errorf("invalid access timestamp")
		}
		switch rec.Status {
		case AccessPending:
			if rec.DecidedAt != nil {
				return nil, fmt.Errorf("invalid decision timestamp")
			}
		default:
			if rec.DecidedAt == nil || rec.DecidedAt.IsZero() || rec.DecidedAt.Before(rec.RequestedAt) || rec.DecidedAt.After(now.Add(time.Minute)) {
				return nil, fmt.Errorf("invalid decision timestamp")
			}
		}
		if _, exists := s.users[rec.UserID]; exists {
			return nil, fmt.Errorf("duplicate access user")
		}
		s.users[rec.UserID] = rec
	}
	return s, nil
}

func (s *AccessStore) Snapshot() []AccessRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshotLocked()
}
func (s *AccessStore) Get(id int64) (AccessRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.users[id]
	return r, ok
}
func (s *AccessStore) Upsert(r AccessRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, exists := s.users[r.UserID]
	s.users[r.UserID] = r
	if err := s.saveLocked(); err != nil {
		if exists {
			s.users[r.UserID] = old
		} else {
			delete(s.users, r.UserID)
		}
		return err
	}
	return nil
}
func (s *AccessStore) Delete(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.users[id]
	if !ok {
		return nil
	}
	delete(s.users, id)
	if err := s.saveLocked(); err != nil {
		s.users[id] = old
		return err
	}
	return nil
}
func (s *AccessStore) snapshotLocked() []AccessRecord {
	out := make([]AccessRecord, 0, len(s.users))
	for _, r := range s.users {
		out = append(out, r)
	}
	return out
}
func (s *AccessStore) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(accessFile{Users: s.snapshotLocked()}, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".telegram-access-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, s.path)
}
