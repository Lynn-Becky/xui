package controller

import (
	"github.com/gin-gonic/gin"
)

type XUIController struct {
	BaseController

	inboundController *InboundController
	settingController *SettingController
}

func NewXUIController(g *gin.RouterGroup) *XUIController {
	a := &XUIController{}
	a.initRouter(g)
	return a
}

func (a *XUIController) initRouter(g *gin.RouterGroup) {
	g = g.Group("/xui")
	g.Use(a.checkLogin)

	g.GET("/", a.index)
	g.GET("/inbounds", a.inbounds)
	g.GET("/setting", a.setting)
	g.GET("/xray", a.xray)
	g.GET("/outbounds", a.outbounds)
	g.GET("/routing", a.routing)
	g.GET("/backup", a.backup)

	a.inboundController = NewInboundController(g)
	a.settingController = NewSettingController(g)
}

func (a *XUIController) index(c *gin.Context) {
	html(c, "index.html", "系统状态", nil)
}

func (a *XUIController) inbounds(c *gin.Context) {
	html(c, "inbounds.html", "入站列表", nil)
}

func (a *XUIController) setting(c *gin.Context) {
	html(c, "setting.html", "设置", gin.H{"page": "setting"})
}

func (a *XUIController) xray(c *gin.Context) {
	html(c, "setting.html", "Xray设置", gin.H{"page": "xray"})
}

func (a *XUIController) outbounds(c *gin.Context) {
	html(c, "setting.html", "出战列表", gin.H{"page": "outbounds"})
}

func (a *XUIController) routing(c *gin.Context) {
	html(c, "routing.html", "路由规则", nil)
}

func (a *XUIController) backup(c *gin.Context) {
	html(c, "backup.html", "备份和恢复", nil)
}
