package service

import (
	_ "embed"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"time"
	"x-ui/database"
	"x-ui/database/model"
	"x-ui/logger"
	"x-ui/util/common"
	"x-ui/util/random"
	"x-ui/util/reflect_util"
	"x-ui/web/entity"
)

//go:embed config.json
var xrayTemplateConfig string

var defaultValueMap = map[string]string{
	"xrayTemplateConfig": xrayTemplateConfig,
	"webListen":          "",
	"webPort":            "54321",
	"webCertFile":        "",
	"webKeyFile":         "",
	// Generated with crypto/rand on first use and persisted; see GetSecret.
	"secret":             "",
	"webBasePath":        "/",
	"timeLocation":       "Asia/Shanghai",
	"tgBotEnable":        "false",
	"tgBotToken":         "",
	"tgBotChatId":        "0",
	"tgRunTime":          "",
	"warp":               "",
	"warpUpdateInterval": "0",
	"warpLastUpdate":     "0",
}

type SettingService struct {
}

func (s *SettingService) GetAllSetting() (*entity.AllSetting, error) {
	db := database.GetDB()
	settings := make([]*model.Setting, 0)
	err := db.Model(model.Setting{}).Find(&settings).Error
	if err != nil {
		return nil, err
	}
	allSetting := &entity.AllSetting{}
	t := reflect.TypeOf(allSetting).Elem()
	v := reflect.ValueOf(allSetting).Elem()
	fields := reflect_util.GetFields(t)

	setSetting := func(key, value string) (err error) {
		defer func() {
			panicErr := recover()
			if panicErr != nil {
				err = errors.New(fmt.Sprint(panicErr))
			}
		}()

		var found bool
		var field reflect.StructField
		for _, f := range fields {
			if f.Tag.Get("json") == key {
				field = f
				found = true
				break
			}
		}

		if !found {
			// 有些设置自动生成，不需要返回到前端给用户修改
			return nil
		}

		fieldV := v.FieldByName(field.Name)
		switch t := fieldV.Interface().(type) {
		case int:
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return err
			}
			fieldV.SetInt(n)
		case string:
			fieldV.SetString(value)
		case bool:
			fieldV.SetBool(value == "true")
		default:
			return common.NewErrorf("unknown field %v type %v", key, t)
		}
		return
	}

	keyMap := map[string]bool{}
	for _, setting := range settings {
		err := setSetting(setting.Key, setting.Value)
		if err != nil {
			return nil, err
		}
		keyMap[setting.Key] = true
	}

	for key, value := range defaultValueMap {
		if keyMap[key] {
			continue
		}
		err := setSetting(key, value)
		if err != nil {
			return nil, err
		}
	}

	return allSetting, nil
}

// preservedOnReset lists the settings that determine how the panel is reached.
//
// A reset that clears these silently returns the panel to plain HTTP on the
// default port at "/", tearing down a configured TLS certificate and discarding
// the random access path — while the confirmation prompt only promises that the
// account is untouched. Anything that changes the panel's exposure stays.
var preservedOnReset = []string{
	"webPort",
	"webBasePath",
	"webCertFile",
	"webKeyFile",
	"secret",
}

func (s *SettingService) ResetSettings() error {
	db := database.GetDB()
	return db.Where("key NOT IN ?", preservedOnReset).Delete(model.Setting{}).Error
}

func (s *SettingService) getSetting(key string) (*model.Setting, error) {
	db := database.GetDB()
	setting := &model.Setting{}
	err := db.Model(model.Setting{}).Where("key = ?", key).First(setting).Error
	if err != nil {
		return nil, err
	}
	return setting, nil
}

func (s *SettingService) saveSetting(key string, value string) error {
	setting, err := s.getSetting(key)
	db := database.GetDB()
	if database.IsNotFound(err) {
		return db.Create(&model.Setting{
			Key:   key,
			Value: value,
		}).Error
	} else if err != nil {
		return err
	}
	setting.Key = key
	setting.Value = value
	return db.Save(setting).Error
}

func (s *SettingService) getString(key string) (string, error) {
	setting, err := s.getSetting(key)
	if database.IsNotFound(err) {
		value, ok := defaultValueMap[key]
		if !ok {
			return "", common.NewErrorf("key <%v> not in defaultValueMap", key)
		}
		return value, nil
	} else if err != nil {
		return "", err
	}
	return setting.Value, nil
}

func (s *SettingService) setString(key string, value string) error {
	return s.saveSetting(key, value)
}

func (s *SettingService) getBool(key string) (bool, error) {
	str, err := s.getString(key)
	if err != nil {
		return false, err
	}
	return strconv.ParseBool(str)
}

func (s *SettingService) setBool(key string, value bool) error {
	return s.setString(key, strconv.FormatBool(value))
}

func (s *SettingService) getInt(key string) (int, error) {
	str, err := s.getString(key)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(str)
}

func (s *SettingService) setInt(key string, value int) error {
	return s.setString(key, strconv.Itoa(value))
}

func (s *SettingService) GetXrayConfigTemplate() (string, error) {
	return s.getString("xrayTemplateConfig")
}

func (s *SettingService) SetXrayConfigTemplate(value string) error {
	return s.setString("xrayTemplateConfig", value)
}

func (s *SettingService) GetWarp() (string, error) {
	return s.getString("warp")
}

func (s *SettingService) SetWarp(value string) error {
	return s.setString("warp", value)
}

func (s *SettingService) GetWarpUpdateInterval() (int, error) {
	return s.getInt("warpUpdateInterval")
}

func (s *SettingService) SetWarpUpdateInterval(value int) error {
	if value < 0 {
		return common.NewError("warp update interval must not be negative")
	}
	return s.setInt("warpUpdateInterval", value)
}

func (s *SettingService) GetWarpLastUpdate() (int64, error) {
	value, err := s.getString("warpLastUpdate")
	if err != nil || value == "" {
		return 0, err
	}
	return strconv.ParseInt(value, 10, 64)
}

func (s *SettingService) SetWarpLastUpdate(value int64) error {
	return s.setString("warpLastUpdate", strconv.FormatInt(value, 10))
}

func (s *SettingService) GetListen() (string, error) {
	return s.getString("webListen")
}

func (s *SettingService) GetTgBotToken() (string, error) {
	return s.getString("tgBotToken")
}

func (s *SettingService) SetTgBotToken(token string) error {
	return s.setString("tgBotToken", token)
}

func (s *SettingService) GetTgBotChatId() (int, error) {
	return s.getInt("tgBotChatId")
}

func (s *SettingService) SetTgBotChatId(chatId int) error {
	return s.setInt("tgBotChatId", chatId)
}

func (s *SettingService) SetTgbotenabled(value bool) error {
	return s.setBool("tgBotEnable", value)
}

func (s *SettingService) GetTgbotenabled() (bool, error) {
	return s.getBool("tgBotEnable")
}

func (s *SettingService) SetTgbotRuntime(time string) error {
	return s.setString("tgRunTime", time)
}

func (s *SettingService) GetTgbotRuntime() (string, error) {
	return s.getString("tgRunTime")
}

func (s *SettingService) GetPort() (int, error) {
	return s.getInt("webPort")
}

func (s *SettingService) SetPort(port int) error {
	return s.setInt("webPort", port)
}

func (s *SettingService) GetCertFile() (string, error) {
	return s.getString("webCertFile")
}

func (s *SettingService) SetCertFile(value string) error {
	return s.setString("webCertFile", value)
}

func (s *SettingService) GetKeyFile() (string, error) {
	return s.getString("webKeyFile")
}

func (s *SettingService) SetKeyFile(value string) error {
	return s.setString("webKeyFile", value)
}

// GetSecret returns the panel secret, generating and persisting one on first
// use.
//
// This key authenticates and encrypts every session cookie, so it must come
// from a cryptographically secure source. It previously came from
// util/random.Seq, which is backed by math/rand.
func (s *SettingService) GetSecret() ([]byte, error) {
	secret, err := s.getString("secret")
	if err != nil {
		return nil, err
	}
	if secret == "" {
		secret, err = random.SecureSeq(64)
		if err != nil {
			return nil, err
		}
		if err := s.saveSetting("secret", secret); err != nil {
			return nil, err
		}
		logger.Info("generated a new panel session secret")
	}
	return []byte(secret), nil
}

func (s *SettingService) GetBasePath() (string, error) {
	basePath, err := s.getString("webBasePath")
	if err != nil {
		return "", err
	}
	return entity.NormalizeBasePath(basePath)
}

func (s *SettingService) SetBasePath(basePath string) error {
	basePath, err := entity.NormalizeBasePath(basePath)
	if err != nil {
		return err
	}
	return s.setString("webBasePath", basePath)
}

func (s *SettingService) GetTimeLocation() (*time.Location, error) {
	l, err := s.getString("timeLocation")
	if err != nil {
		return nil, err
	}
	location, err := time.LoadLocation(l)
	if err != nil {
		defaultLocation := defaultValueMap["timeLocation"]
		logger.Errorf("location <%v> not exist, using default location: %v", l, defaultLocation)
		return time.LoadLocation(defaultLocation)
	}
	return location, nil
}

func (s *SettingService) UpdateAllSetting(allSetting *entity.AllSetting) error {
	if err := allSetting.CheckValid(); err != nil {
		return err
	}

	v := reflect.ValueOf(allSetting).Elem()
	t := reflect.TypeOf(allSetting).Elem()
	fields := reflect_util.GetFields(t)
	errs := make([]error, 0)
	for _, field := range fields {
		key := field.Tag.Get("json")
		fieldV := v.FieldByName(field.Name)
		value := fmt.Sprint(fieldV.Interface())
		err := s.saveSetting(key, value)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return common.Combine(errs...)
}
