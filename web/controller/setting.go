package controller

import (
	"errors"
	"github.com/gin-gonic/gin"
	"strings"
	"time"
	"x-ui/web/entity"
	"x-ui/web/service"
	"x-ui/web/session"
)

type updateUserForm struct {
	OldUsername string `json:"oldUsername" form:"oldUsername"`
	OldPassword string `json:"oldPassword" form:"oldPassword"`
	NewUsername string `json:"newUsername" form:"newUsername"`
	NewPassword string `json:"newPassword" form:"newPassword"`
}

type SettingController struct {
	settingService service.SettingService
	userService    service.UserService
	panelService   service.PanelService
	xrayService    service.XrayService
	warpService    *service.WarpService
}

func NewSettingController(g *gin.RouterGroup) *SettingController {
	a := &SettingController{warpService: service.NewWarpService()}
	a.initRouter(g)
	return a
}

func (a *SettingController) initRouter(g *gin.RouterGroup) {
	g = g.Group("/setting")

	g.POST("/all", a.getAllSetting)
	g.POST("/update", a.updateSetting)
	g.POST("/updateUser", a.updateUser)
	g.POST("/restartPanel", a.restartPanel)
	g.POST("/warp/:action", a.warp)
}

type warpRegisterForm struct {
	PrivateKey string `json:"privateKey" form:"privateKey"`
	PublicKey  string `json:"publicKey" form:"publicKey"`
}

type warpLicenseForm struct {
	License string `json:"license" form:"license"`
}

type warpIntervalForm struct {
	Interval int `json:"interval" form:"interval"`
}

func (a *SettingController) warp(c *gin.Context) {
	action := c.Param("action")
	var response string
	var err error
	switch action {
	case "data":
		response, err = a.warpService.GetWarpData()
	case "del":
		err = a.warpService.DelWarpData()
		if err == nil {
			_ = a.settingService.SetWarpUpdateInterval(0)
			_ = a.settingService.SetWarpLastUpdate(0)
		}
	case "config":
		response, err = a.warpService.GetWarpConfig()
	case "reg":
		var form warpRegisterForm
		if err = c.ShouldBind(&form); err == nil {
			response, err = a.warpService.RegWarp(strings.TrimSpace(form.PrivateKey), strings.TrimSpace(form.PublicKey))
		}
	case "changeIp":
		response, err = a.warpService.ChangeWarpIP()
		if err == nil {
			a.xrayService.SetToNeedRestart()
			_ = a.settingService.SetWarpLastUpdate(time.Now().Unix())
		}
	case "license":
		var form warpLicenseForm
		if err = c.ShouldBind(&form); err == nil {
			response, err = a.warpService.SetWarpLicense(form.License)
		}
	case "interval":
		var form warpIntervalForm
		if err = c.ShouldBind(&form); err == nil {
			err = a.settingService.SetWarpUpdateInterval(form.Interval)
			if err == nil && form.Interval > 0 {
				_ = a.settingService.SetWarpLastUpdate(time.Now().Unix())
			}
		}
	default:
		err = errors.New("unsupported warp action")
	}
	jsonObj(c, response, err)
}

func (a *SettingController) getAllSetting(c *gin.Context) {
	allSetting, err := a.settingService.GetAllSetting()
	if err != nil {
		jsonMsg(c, "获取设置", err)
		return
	}
	jsonObj(c, allSetting, nil)
}

func (a *SettingController) updateSetting(c *gin.Context) {
	allSetting := &entity.AllSetting{}
	err := c.ShouldBind(allSetting)
	if err != nil {
		jsonMsg(c, "修改设置", err)
		return
	}
	oldXrayTemplate, oldTemplateErr := a.settingService.GetXrayConfigTemplate()
	err = a.settingService.UpdateAllSetting(allSetting)
	if err == nil && oldTemplateErr == nil && oldXrayTemplate != allSetting.XrayTemplateConfig {
		a.xrayService.SetToNeedRestart()
	}
	jsonMsg(c, "修改设置", err)
}

func (a *SettingController) updateUser(c *gin.Context) {
	form := &updateUserForm{}
	err := c.ShouldBind(form)
	if err != nil {
		jsonMsg(c, "修改用户", err)
		return
	}
	user := session.GetLoginUser(c)
	if user.Username != form.OldUsername || user.Password != form.OldPassword {
		jsonMsg(c, "修改用户", errors.New("原用户名或原密码错误"))
		return
	}
	if form.NewUsername == "" || form.NewPassword == "" {
		jsonMsg(c, "修改用户", errors.New("新用户名和新密码不能为空"))
		return
	}
	err = a.userService.UpdateUser(user.Id, form.NewUsername, form.NewPassword)
	if err == nil {
		user.Username = form.NewUsername
		user.Password = form.NewPassword
		session.SetLoginUser(c, user)
	}
	jsonMsg(c, "修改用户", err)
}

func (a *SettingController) restartPanel(c *gin.Context) {
	err := a.panelService.RestartPanel(time.Second * 3)
	jsonMsg(c, "重启面板", err)
}
