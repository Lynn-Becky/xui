package entity

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"strings"
	"time"
	"x-ui/util/common"
	"x-ui/xray"
)

type Msg struct {
	Success bool        `json:"success"`
	Msg     string      `json:"msg"`
	Obj     interface{} `json:"obj"`
}

type Pager struct {
	Current  int         `json:"current"`
	PageSize int         `json:"page_size"`
	Total    int         `json:"total"`
	OrderBy  string      `json:"order_by"`
	Desc     bool        `json:"desc"`
	Key      string      `json:"key"`
	List     interface{} `json:"list"`
}

type AllSetting struct {
	WebListen          string `json:"webListen" form:"webListen"`
	WebPort            int    `json:"webPort" form:"webPort"`
	WebCertFile        string `json:"webCertFile" form:"webCertFile"`
	WebKeyFile         string `json:"webKeyFile" form:"webKeyFile"`
	WebBasePath        string `json:"webBasePath" form:"webBasePath"`
	TgBotEnable        bool   `json:"tgBotEnable" form:"tgBotEnable"`
	TgBotToken         string `json:"tgBotToken" form:"tgBotToken"`
	TgBotChatId        int    `json:"tgBotChatId" form:"tgBotChatId"`
	TgRunTime          string `json:"tgRunTime" form:"tgRunTime"`
	XrayTemplateConfig string `json:"xrayTemplateConfig" form:"xrayTemplateConfig"`
	WarpUpdateInterval int    `json:"warpUpdateInterval" form:"warpUpdateInterval"`

	TimeLocation string `json:"timeLocation" form:"timeLocation"`
}

// NormalizeBasePath converts a panel URI path to its canonical /…/ form.
// Keep the character rules in line with 3x-ui: a path must not contain a
// backslash, space, or control character, because those values are ambiguous
// when used for routing and in shell-provided panel URLs.
func NormalizeBasePath(basePath string) (string, error) {
	for _, r := range basePath {
		if r == '\\' || r == ' ' || r < 0x20 || r == 0x7f {
			return "", common.NewError("URI path contains an invalid character: web base path")
		}
	}
	if !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}
	if !strings.HasSuffix(basePath, "/") {
		basePath += "/"
	}
	return basePath, nil
}

func (s *AllSetting) CheckValid() error {
	if s.WebListen != "" {
		ip := net.ParseIP(s.WebListen)
		if ip == nil {
			return common.NewError("web listen is not valid ip:", s.WebListen)
		}
	}

	if s.WebPort <= 0 || s.WebPort > 65535 {
		return common.NewError("web port is not a valid port:", s.WebPort)
	}

	if (s.WebCertFile == "") != (s.WebKeyFile == "") {
		return common.NewError("both web certificate and key files must be configured together")
	}
	if s.WebCertFile != "" {
		_, err := tls.LoadX509KeyPair(s.WebCertFile, s.WebKeyFile)
		if err != nil {
			return common.NewErrorf("cert file <%v> or key file <%v> invalid: %v", s.WebCertFile, s.WebKeyFile, err)
		}
	}

	basePath, err := NormalizeBasePath(s.WebBasePath)
	if err != nil {
		return err
	}
	s.WebBasePath = basePath

	xrayConfig := &xray.Config{}
	err = json.Unmarshal([]byte(s.XrayTemplateConfig), xrayConfig)
	if err != nil {
		return common.NewError("xray template config invalid:", err)
	}
	if err := xrayConfig.ValidateOutboundConfigs(); err != nil {
		return common.NewError("xray template config invalid outbounds:", err)
	}
	if s.WarpUpdateInterval < 0 {
		return common.NewError("warp update interval must not be negative")
	}

	_, err = time.LoadLocation(s.TimeLocation)
	if err != nil {
		return common.NewError("time location not exist:", s.TimeLocation)
	}

	return nil
}
