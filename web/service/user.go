package service

import (
	"errors"
	"x-ui/database"
	"x-ui/database/model"
	"x-ui/logger"

	"gorm.io/gorm"
)

type UserService struct {
}

func (s *UserService) GetFirstUser() (*model.User, error) {
	db := database.GetDB()

	user := &model.User{}
	err := db.Model(model.User{}).
		First(user).
		Error
	if err != nil {
		return nil, err
	}
	return user, nil
}

// GetUserById loads a single account. checkLogin uses it to turn the user id in
// the session cookie back into the current database row on every request.
func (s *UserService) GetUserById(id int) (*model.User, error) {
	if id <= 0 {
		return nil, gorm.ErrRecordNotFound
	}
	db := database.GetDB()
	user := &model.User{}
	err := db.Model(model.User{}).Where("id = ?", id).First(user).Error
	if err != nil {
		return nil, err
	}
	return user, nil
}

// CheckUser verifies a login. The password is never compared in SQL: the row is
// fetched by username and the credential is checked with bcrypt, so the stored
// value can be a hash.
func (s *UserService) CheckUser(username string, password string) *model.User {
	db := database.GetDB()

	user := &model.User{}
	err := db.Model(model.User{}).
		Where("username = ?", username).
		First(user).
		Error
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Warning("check user err:", err)
		}
		// Spend the same time as a real comparison so an unknown username is
		// not distinguishable from a wrong password by response timing.
		model.EqualizeVerifyTiming(password)
		return nil
	}

	ok, needsRehash := model.VerifyPassword(user.Password, password)
	if !ok {
		return nil
	}
	if needsRehash {
		// Row predates password hashing. Upgrade it in place now that we hold
		// the verified cleartext; a failure here must not block the login.
		if err := s.setPassword(user, password); err != nil {
			logger.Warning("upgrade stored password to bcrypt failed:", err)
		}
	}
	return user
}

// setPassword stores a bcrypt hash of password for user and keeps the in-memory
// copy consistent with the row.
func (s *UserService) setPassword(user *model.User, password string) error {
	hash, err := model.HashPassword(password)
	if err != nil {
		return err
	}
	db := database.GetDB()
	if err := db.Model(model.User{}).
		Where("id = ?", user.Id).
		Update("password", hash).
		Error; err != nil {
		return err
	}
	user.Password = hash
	return nil
}

func (s *UserService) UpdateUser(id int, username string, password string) error {
	if username == "" {
		return errors.New("username can not be empty")
	}
	if password == "" {
		return errors.New("password can not be empty")
	}
	hash, err := model.HashPassword(password)
	if err != nil {
		return err
	}
	db := database.GetDB()
	// A single statement: the previous two chained Update calls issued two
	// writes and could leave the row with a new username but the old password.
	return db.Model(model.User{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"username": username,
			"password": hash,
		}).
		Error
}

func (s *UserService) UpdateFirstUser(username string, password string) error {
	if username == "" {
		return errors.New("username can not be empty")
	} else if password == "" {
		return errors.New("password can not be empty")
	}
	hash, err := model.HashPassword(password)
	if err != nil {
		return err
	}
	db := database.GetDB()
	user := &model.User{}
	err = db.Model(model.User{}).First(user).Error
	if database.IsNotFound(err) {
		user.Username = username
		user.Password = hash
		return db.Model(model.User{}).Create(user).Error
	} else if err != nil {
		return err
	}
	user.Username = username
	user.Password = hash
	return db.Save(user).Error
}
