package telegram

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAccessStoreRejectsDuplicateAndInvalidRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.json")
	data := []byte(`{"users":[{"user_id":2,"chat_id":2,"status":"approved","requested_at":"2026-01-01T00:00:00Z","decided_at":"2026-01-01T00:00:01Z"},{"user_id":2,"chat_id":2,"status":"approved","requested_at":"2026-01-01T00:00:00Z","decided_at":"2026-01-01T00:00:01Z"}]}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewAccessStore(path, 99); err == nil {
		t.Fatal("expected duplicate rejection")
	}
}

func TestAccessStoreAtomicRollbackOnSaveFailure(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "missing", "access.json")
	s, err := NewAccessStore(path, 99)
	if err != nil {
		t.Fatal(err)
	}
	rec := AccessRecord{UserID: 2, ChatID: 2, Status: AccessPending, RequestedAt: time.Now()}
	if err := s.Upsert(rec); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get(2); !ok {
		t.Fatal("record not stored")
	}
	if err := os.RemoveAll(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Dir(path), []byte("block"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Upsert(AccessRecord{UserID: 2, ChatID: 2, Status: AccessDenied, RequestedAt: rec.RequestedAt, DecidedAt: ptr(time.Now())}); err == nil {
		t.Fatal("expected save failure")
	}
	got, ok := s.Get(2)
	if !ok || got.Status != AccessPending {
		t.Fatalf("state changed after failed save: %+v %v", got, ok)
	}
}

func ptr(t time.Time) *time.Time { return &t }
