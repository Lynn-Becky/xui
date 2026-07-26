package database

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"x-ui/config"
	"x-ui/database/model"
	"x-ui/util/random"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var db *gorm.DB

func initUser() error {
	err := db.AutoMigrate(&model.User{})
	if err != nil {
		return err
	}
	var count int64
	err = db.Model(&model.User{}).Count(&count).Error
	if err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	// Never seed a fixed credential. A panel that boots with admin/admin on a
	// well-known port is found by internet-wide scanners within minutes, and
	// the Docker image and the manual install steps both reach this path
	// without the installer's credential provisioning.
	//
	// The generated password is printed once so the operator can recover it
	// from the service log (journalctl -u x-ui, or docker logs).
	password, err := random.SecureSeq(24)
	if err != nil {
		return err
	}
	hash, err := model.HashPassword(password)
	if err != nil {
		return err
	}
	user := &model.User{
		Username: "admin",
		Password: hash,
	}
	if err := db.Create(user).Error; err != nil {
		return err
	}

	log.Printf("=====================================================")
	log.Printf(" x-ui: created the initial administrator account")
	log.Printf("   username: admin")
	log.Printf("   password: %s", password)
	log.Printf(" This is shown only once. Change it after logging in.")
	log.Printf("=====================================================")
	return nil
}

func initInbound() error {
	return db.AutoMigrate(&model.Inbound{})
}

func initSetting() error {
	return db.AutoMigrate(&model.Setting{})
}

func InitDB(dbPath string) error {
	dir := path.Dir(dbPath)
	// 0700, not fs.ModeDir: fs.ModeDir is a type bit, so its permission bits
	// are zero and the directory was previously created with mode 0000.
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		return err
	}

	var gormLogger logger.Interface

	if config.IsDebug() {
		gormLogger = logger.Default
	} else {
		gormLogger = logger.Discard
	}

	c := &gorm.Config{
		Logger: gormLogger,
	}
	db, err = gorm.Open(sqlite.Open(dbPath), c)
	if err != nil {
		return err
	}

	// go-sqlite3 creates the database 0644. The file holds every inbound's
	// secrets and the administrator credential hash, and on a Docker bind mount
	// the host directory already exists so the 0700 above does not shield it.
	if err := os.Chmod(dbPath, 0600); err != nil && !os.IsNotExist(err) {
		return err
	}

	err = initUser()
	if err != nil {
		return err
	}
	err = initInbound()
	if err != nil {
		return err
	}
	err = initSetting()
	if err != nil {
		return err
	}

	return nil
}

func GetDB() *gorm.DB {
	return db
}

func Checkpoint() error {
	if db == nil {
		return fmt.Errorf("database is not initialized")
	}
	return db.Exec("PRAGMA wal_checkpoint(TRUNCATE)").Error
}

func CloseDB() error {
	if db == nil {
		return nil
	}
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// BackupTo writes a transactionally consistent SQLite backup to dst.
func BackupTo(dst io.Writer) error {
	if db == nil {
		return fmt.Errorf("database is not initialized")
	}

	// VACUUM INTO creates a consistent snapshot; copy that completed temporary
	// database to the response instead of reading a live database file.
	tempFile, err := os.CreateTemp("", "x-ui-backup-*.db")
	if err != nil {
		return err
	}
	tempPath := tempFile.Name()
	if err := tempFile.Close(); err != nil {
		return err
	}
	defer os.Remove(tempPath)
	if err := os.Remove(tempPath); err != nil {
		return err
	}
	if err := db.Exec("VACUUM INTO ?", tempPath).Error; err != nil {
		return err
	}
	backup, err := os.Open(tempPath)
	if err != nil {
		return err
	}
	defer backup.Close()
	_, err = io.Copy(dst, backup)
	return err
}

// ValidateSQLiteDB verifies the uploaded backup without mutating it.
func ValidateSQLiteDB(dbPath string) error {
	info, err := os.Stat(dbPath)
	if err != nil {
		return err
	}
	if info.IsDir() || info.Size() == 0 {
		return fmt.Errorf("database file is empty")
	}

	dsn := "file:" + filepath.ToSlash(dbPath) + "?mode=ro"
	validationDB, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return err
	}
	defer validationDB.Close()

	var result string
	if err := validationDB.QueryRow("PRAGMA quick_check").Scan(&result); err != nil {
		return err
	}
	if !strings.EqualFold(result, "ok") {
		return fmt.Errorf("database integrity check failed: %s", result)
	}

	var tableCount int
	err = validationDB.QueryRow(
		"SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ('users', 'inbounds', 'settings')",
	).Scan(&tableCount)
	if err != nil {
		return err
	}
	if tableCount != 3 {
		return fmt.Errorf("database is not an x-ui backup")
	}
	return nil
}

func IsNotFound(err error) bool {
	return err == gorm.ErrRecordNotFound
}
