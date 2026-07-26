package database

import (
	"path/filepath"
	"strings"
	"testing"
	"x-ui/database/model"
)

func openTestDB(t *testing.T) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "x-ui.db")
	if err := InitDB(dbPath); err != nil {
		if strings.Contains(err.Error(), "CGO_ENABLED=0") {
			t.Skip("go-sqlite3 runtime is unavailable with CGO disabled")
		}
		t.Fatalf("InitDB() error = %v", err)
	}
	t.Cleanup(func() { _ = CloseDB() })
}

func userCount(t *testing.T) int64 {
	t.Helper()
	var count int64
	if err := db.Model(&model.User{}).Count(&count).Error; err != nil {
		t.Fatalf("count users: %v", err)
	}
	return count
}

// Opening the database must not seed an account.
//
// Every CLI subcommand opens the database, so seeding in InitDB meant the
// installer created a throwaway administrator and printed its password moments
// before setting the real credentials — two different passwords in a single
// install, the first of them meaningless.
func TestInitDBDoesNotCreateAnAccount(t *testing.T) {
	openTestDB(t)

	if got := userCount(t); got != 0 {
		t.Fatalf("InitDB() created %d user(s), want 0", got)
	}
}

func TestEnsureInitialUserSeedsOnceWithAHashedPassword(t *testing.T) {
	openTestDB(t)

	if err := EnsureInitialUser(); err != nil {
		t.Fatalf("EnsureInitialUser() error = %v", err)
	}
	if got := userCount(t); got != 1 {
		t.Fatalf("after seeding there are %d user(s), want 1", got)
	}

	seeded := &model.User{}
	if err := db.Model(&model.User{}).First(seeded).Error; err != nil {
		t.Fatalf("load seeded user: %v", err)
	}
	if seeded.Username != "admin" {
		t.Errorf("username = %q, want %q", seeded.Username, "admin")
	}
	if !model.IsHashedPassword(seeded.Password) {
		t.Errorf("seeded password is not a bcrypt hash: %q", seeded.Password)
	}
	// Never a fixed credential.
	if ok, _ := model.VerifyPassword(seeded.Password, "admin"); ok {
		t.Error("seeded account accepts the password \"admin\"")
	}

	// Idempotent: restarting the panel must not replace the credential.
	if err := EnsureInitialUser(); err != nil {
		t.Fatalf("EnsureInitialUser() second call error = %v", err)
	}
	if got := userCount(t); got != 1 {
		t.Fatalf("second call created another account: %d user(s)", got)
	}
	again := &model.User{}
	if err := db.Model(&model.User{}).First(again).Error; err != nil {
		t.Fatalf("reload seeded user: %v", err)
	}
	if again.Password != seeded.Password {
		t.Error("EnsureInitialUser() rewrote an existing credential")
	}
}

// The installer sets credentials before the panel ever starts; the later seed
// attempt must then do nothing.
func TestEnsureInitialUserSkipsWhenInstallerAlreadyProvisioned(t *testing.T) {
	openTestDB(t)

	hash, err := model.HashPassword("installer-chosen-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if err := db.Create(&model.User{Username: "operator", Password: hash}).Error; err != nil {
		t.Fatalf("create provisioned user: %v", err)
	}

	if err := EnsureInitialUser(); err != nil {
		t.Fatalf("EnsureInitialUser() error = %v", err)
	}
	if got := userCount(t); got != 1 {
		t.Fatalf("EnsureInitialUser() added an account: %d user(s), want 1", got)
	}
	kept := &model.User{}
	if err := db.Model(&model.User{}).First(kept).Error; err != nil {
		t.Fatalf("load user: %v", err)
	}
	if kept.Username != "operator" || kept.Password != hash {
		t.Error("EnsureInitialUser() overwrote the installer's credentials")
	}
}
