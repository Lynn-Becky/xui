package database

import (
	"database/sql"
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"x-ui/config"
	"x-ui/database/model"
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
	if count == 0 {
		user := &model.User{
			Username: "admin",
			Password: "admin",
		}
		return db.Create(user).Error
	}
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
	err := os.MkdirAll(dir, fs.ModeDir)
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
