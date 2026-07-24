package database

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateSQLiteDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "x-ui.db")
	if err := InitDB(dbPath); err != nil {
		if strings.Contains(err.Error(), "CGO_ENABLED=0") {
			t.Skip("go-sqlite3 runtime is unavailable with CGO disabled")
		}
		t.Fatalf("InitDB() error = %v", err)
	}
	if err := Checkpoint(); err != nil {
		t.Fatalf("Checkpoint() error = %v", err)
	}
	if err := ValidateSQLiteDB(dbPath); err != nil {
		t.Fatalf("ValidateSQLiteDB() rejected an x-ui database: %v", err)
	}
	var backup bytes.Buffer
	if err := BackupTo(&backup); err != nil {
		t.Fatalf("BackupTo() error = %v", err)
	}
	backupPath := filepath.Join(t.TempDir(), "backup.db")
	if err := os.WriteFile(backupPath, backup.Bytes(), 0600); err != nil {
		t.Fatalf("WriteFile(backup) error = %v", err)
	}
	if err := ValidateSQLiteDB(backupPath); err != nil {
		t.Fatalf("BackupTo() produced an invalid backup: %v", err)
	}
	if err := CloseDB(); err != nil {
		t.Fatalf("CloseDB() error = %v", err)
	}

	invalidPath := filepath.Join(t.TempDir(), "invalid.db")
	if err := os.WriteFile(invalidPath, []byte("not a sqlite database"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := ValidateSQLiteDB(invalidPath); err == nil {
		t.Fatal("ValidateSQLiteDB() accepted a non-SQLite file")
	}
}
