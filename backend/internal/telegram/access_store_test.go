package telegram

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

var (
	accessRequestedAt = time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)
	accessDecidedAt   = accessRequestedAt.Add(time.Minute)
)

func TestAccessStoreMissingFileStartsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "access.json")

	store, err := NewAccessStore(path, 99)
	if err != nil {
		t.Fatalf("NewAccessStore() error = %v", err)
	}
	if got := store.Snapshot(); len(got) != 0 {
		t.Fatalf("Snapshot() = %+v, want empty", got)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("missing store was created or stat failed unexpectedly: %v", err)
	}
}

func TestAccessStoreRejectsCorruptJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.json")
	if err := os.WriteFile(path, []byte(`{"users":[`), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := NewAccessStore(path, 99); err == nil {
		t.Fatal("NewAccessStore() succeeded for corrupt JSON")
	}
}

func TestAccessStoreRejectsInvalidRecords(t *testing.T) {
	validPending := AccessRecord{
		UserID:      2,
		ChatID:      2,
		Username:    "pending-user",
		DisplayName: "Pending User",
		Status:      AccessPending,
		RequestedAt: accessRequestedAt,
	}
	validApproved := AccessRecord{
		UserID:      3,
		ChatID:      3,
		Username:    "approved-user",
		DisplayName: "Approved User",
		Status:      AccessApproved,
		RequestedAt: accessRequestedAt,
		DecidedAt:   timePointer(accessDecidedAt),
	}
	validDenied := AccessRecord{
		UserID:      4,
		ChatID:      4,
		Username:    "denied-user",
		DisplayName: "Denied User",
		Status:      AccessDenied,
		RequestedAt: accessRequestedAt,
		DecidedAt:   timePointer(accessDecidedAt),
	}

	tests := []struct {
		name    string
		records []AccessRecord
	}{
		{
			name:    "zero user ID",
			records: []AccessRecord{withAccessIDs(validPending, 0, 2)},
		},
		{
			name:    "negative user ID",
			records: []AccessRecord{withAccessIDs(validPending, -1, 2)},
		},
		{
			name:    "zero chat ID",
			records: []AccessRecord{withAccessIDs(validPending, 2, 0)},
		},
		{
			name:    "negative chat ID",
			records: []AccessRecord{withAccessIDs(validPending, 2, -1)},
		},
		{
			name:    "chat ID differs from user ID",
			records: []AccessRecord{withAccessIDs(validPending, 2, 3)},
		},
		{
			name:    "owner appears in access file",
			records: []AccessRecord{withAccessIDs(validPending, 99, 99)},
		},
		{
			name: "unknown status",
			records: []AccessRecord{func() AccessRecord {
				record := validPending
				record.Status = AccessStatus("unknown")
				return record
			}()},
		},
		{
			name:    "duplicate user ID",
			records: []AccessRecord{validPending, validPending},
		},
		{
			name: "zero requested timestamp",
			records: []AccessRecord{func() AccessRecord {
				record := validPending
				record.RequestedAt = time.Time{}
				return record
			}()},
		},
		{
			name: "requested timestamp too far in future",
			records: []AccessRecord{func() AccessRecord {
				record := validPending
				record.RequestedAt = time.Now().Add(24 * time.Hour)
				return record
			}()},
		},
		{
			name: "pending record has decision timestamp",
			records: []AccessRecord{func() AccessRecord {
				record := validPending
				record.DecidedAt = timePointer(accessDecidedAt)
				return record
			}()},
		},
		{
			name: "approved record lacks decision timestamp",
			records: []AccessRecord{func() AccessRecord {
				record := validApproved
				record.DecidedAt = nil
				return record
			}()},
		},
		{
			name: "denied record lacks decision timestamp",
			records: []AccessRecord{func() AccessRecord {
				record := validDenied
				record.DecidedAt = nil
				return record
			}()},
		},
		{
			name: "approved record has zero decision timestamp",
			records: []AccessRecord{func() AccessRecord {
				record := validApproved
				record.DecidedAt = timePointer(time.Time{})
				return record
			}()},
		},
		{
			name: "denied decision precedes request",
			records: []AccessRecord{func() AccessRecord {
				record := validDenied
				record.DecidedAt = timePointer(accessRequestedAt.Add(-time.Second))
				return record
			}()},
		},
		{
			name: "approved decision is too far in future",
			records: []AccessRecord{func() AccessRecord {
				record := validApproved
				record.DecidedAt = timePointer(time.Now().Add(24 * time.Hour))
				return record
			}()},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "access.json")
			writeAccessFile(t, path, tt.records, 0600)

			if _, err := NewAccessStore(path, 99); err == nil {
				t.Fatal("NewAccessStore() succeeded for invalid access file")
			}
		})
	}
}

func TestAccessStorePersistsReloadsAndDeletes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "access.json")
	store, err := NewAccessStore(path, 99)
	if err != nil {
		t.Fatal(err)
	}
	pending := AccessRecord{
		UserID:      2,
		ChatID:      2,
		Username:    "alice",
		DisplayName: "Alice",
		Status:      AccessPending,
		RequestedAt: accessRequestedAt,
	}
	approved := pending
	approved.Status = AccessApproved
	approved.DecidedAt = timePointer(accessDecidedAt)

	if err := store.Upsert(pending); err != nil {
		t.Fatalf("Upsert(pending) error = %v", err)
	}
	assertAccessRecord(t, store, pending)
	if err := store.Upsert(approved); err != nil {
		t.Fatalf("Upsert(approved) error = %v", err)
	}
	assertAccessRecord(t, store, approved)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("store mode = %04o, want 0600", got)
	}

	reloaded, err := NewAccessStore(path, 99)
	if err != nil {
		t.Fatalf("reload error = %v", err)
	}
	assertAccessRecord(t, reloaded, approved)

	if err := reloaded.Delete(2); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, ok := reloaded.Get(2); ok {
		t.Fatal("deleted record remains in memory")
	}
	if err := reloaded.Delete(2); err != nil {
		t.Fatalf("Delete() of absent record error = %v", err)
	}

	empty, err := NewAccessStore(path, 99)
	if err != nil {
		t.Fatalf("reload after delete error = %v", err)
	}
	if got := empty.Snapshot(); len(got) != 0 {
		t.Fatalf("reloaded Snapshot() = %+v, want empty", got)
	}
}

func TestAccessStoreRollbackOnMkdirFailure(t *testing.T) {
	root := t.TempDir()
	blocker := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(blocker, []byte("block"), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := NewAccessStore(filepath.Join(root, "initial-access.json"), 99)
	if err != nil {
		t.Fatal(err)
	}
	store.path = filepath.Join(blocker, "nested", "access.json")
	record := pendingAccessRecord(2)

	if err := store.Upsert(record); err == nil {
		t.Fatal("Upsert() succeeded despite mkdir failure")
	}
	if _, ok := store.Get(record.UserID); ok {
		t.Fatal("failed insert remained in memory")
	}
}

func TestAccessStoreRollbackOnWriteFailure(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "access.json")
	original := pendingAccessRecord(2)
	writeAccessFile(t, path, []AccessRecord{original}, 0600)
	store, err := NewAccessStore(path, 99)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(root, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(root, 0700); err != nil {
			t.Errorf("restore directory permissions: %v", err)
		}
	})
	probe, probeErr := os.CreateTemp(root, ".write-probe-*")
	if probeErr == nil {
		name := probe.Name()
		_ = probe.Close()
		_ = os.Remove(name)
		t.Skip("filesystem user can write to a 0500 directory")
	}

	updated := original
	updated.Status = AccessDenied
	updated.DecidedAt = timePointer(accessDecidedAt)
	if err := store.Upsert(updated); err == nil {
		t.Fatal("Upsert() succeeded despite write failure")
	}
	assertAccessRecord(t, store, original)
}

func TestAccessStoreRollbackOnRenameFailure(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "access.json")
	original := pendingAccessRecord(2)
	writeAccessFile(t, path, []AccessRecord{original}, 0600)
	store, err := NewAccessStore(path, 99)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}

	if err := store.Delete(original.UserID); err == nil {
		t.Fatal("Delete() succeeded despite rename failure")
	}
	assertAccessRecord(t, store, original)
}

func pendingAccessRecord(id int64) AccessRecord {
	return AccessRecord{
		UserID:      id,
		ChatID:      id,
		DisplayName: "Pending User",
		Status:      AccessPending,
		RequestedAt: accessRequestedAt,
	}
}

func withAccessIDs(record AccessRecord, userID, chatID int64) AccessRecord {
	record.UserID = userID
	record.ChatID = chatID
	return record
}

func timePointer(value time.Time) *time.Time {
	return &value
}

func writeAccessFile(t *testing.T, path string, records []AccessRecord, mode os.FileMode) {
	t.Helper()
	data, err := json.Marshal(accessFile{Users: records})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

func assertAccessRecord(t *testing.T, store *AccessStore, want AccessRecord) {
	t.Helper()
	got, ok := store.Get(want.UserID)
	if !ok {
		t.Fatalf("Get(%d) did not find record", want.UserID)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Get(%d) = %+v, want %+v", want.UserID, got, want)
	}
}
