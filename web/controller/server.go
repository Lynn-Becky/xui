package controller

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
	"x-ui/web/global"
	"x-ui/web/service"
)

type ServerController struct {
	BaseController

	serverService service.ServerService

	lastStatus        *service.Status
	lastGetStatusTime time.Time

	lastVersions        []string
	lastGetVersionsTime time.Time
}

func NewServerController(g *gin.RouterGroup) *ServerController {
	a := &ServerController{
		lastGetStatusTime: time.Now(),
	}
	a.initRouter(g)
	a.startTask()
	return a
}

func (a *ServerController) initRouter(g *gin.RouterGroup) {
	g = g.Group("/server")

	g.Use(a.checkLogin, a.checkCSRF)
	g.POST("/status", a.status)
	g.POST("/getXrayVersion", a.getXrayVersion)
	g.POST("/installXray/:version", a.installXray)
	g.POST("/stopXrayService", a.stopXrayService)
	g.POST("/restartXrayService", a.restartXrayService)
	g.POST("/updateGeofile", a.updateGeofile)
	g.POST("/updateGeofile/:fileName", a.updateGeofile)
	g.GET("/getDb", a.getDb)
	g.POST("/importDB", a.importDB)
	g.POST("/getNewX25519Cert", a.getNewX25519Cert)
	g.POST("/getNewMldsa65", a.getNewMldsa65)
	g.POST("/getNewVlessEnc", a.getNewVlessEnc)
}

func (a *ServerController) refreshStatus() {
	a.lastStatus = a.serverService.GetStatus(a.lastStatus)
}

func (a *ServerController) startTask() {
	webServer := global.GetWebServer()
	c := webServer.GetCron()
	c.AddFunc("@every 2s", func() {
		now := time.Now()
		if now.Sub(a.lastGetStatusTime) > time.Minute*3 {
			return
		}
		a.refreshStatus()
	})
}

func (a *ServerController) status(c *gin.Context) {
	a.lastGetStatusTime = time.Now()

	jsonObj(c, a.lastStatus, nil)
}

func (a *ServerController) getXrayVersion(c *gin.Context) {
	now := time.Now()
	if now.Sub(a.lastGetVersionsTime) <= time.Minute {
		jsonObj(c, a.lastVersions, nil)
		return
	}

	versions, err := a.serverService.GetXrayVersions()
	if err != nil {
		jsonMsg(c, "获取版本", err)
		return
	}

	a.lastVersions = versions
	a.lastGetVersionsTime = time.Now()

	jsonObj(c, versions, nil)
}

func (a *ServerController) installXray(c *gin.Context) {
	version := c.Param("version")
	err := a.serverService.UpdateXray(version)
	jsonMsg(c, "安装 xray", err)
}

func (a *ServerController) stopXrayService(c *gin.Context) {
	err := a.serverService.StopXrayService()
	jsonMsg(c, "停止 Xray", err)
}

func (a *ServerController) restartXrayService(c *gin.Context) {
	err := a.serverService.RestartXrayService()
	jsonMsg(c, "重启 Xray", err)
}

func (a *ServerController) updateGeofile(c *gin.Context) {
	fileName := c.Param("fileName")
	if fileName != "" && !a.serverService.IsValidGeofileName(fileName) {
		jsonMsg(c, "更新 Geo 文件", service.ErrInvalidGeofileName)
		return
	}
	err := a.serverService.UpdateGeofile(fileName)
	jsonMsg(c, "更新 Geo 文件", err)
}

func (a *ServerController) getDb(c *gin.Context) {
	data, err := a.serverService.GetDb()
	if err != nil {
		jsonMsg(c, "备份数据库", err)
		return
	}
	c.Header("Content-Disposition", "attachment; filename="+a.serverService.BackupFilename())
	c.Data(http.StatusOK, "application/octet-stream", data)
}

func (a *ServerController) importDB(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, service.MaxDatabaseUploadSize+(1<<20))
	file, _, err := c.Request.FormFile("db")
	if err != nil {
		jsonMsg(c, "读取数据库备份", err)
		return
	}
	defer file.Close()
	if err := a.serverService.ImportDB(file); err != nil {
		jsonMsg(c, "恢复数据库", err)
		return
	}
	jsonMsg(c, "恢复数据库", nil)
}

func (a *ServerController) getNewX25519Cert(c *gin.Context) {
	keyPair, err := a.serverService.GetNewX25519Cert()
	jsonObj(c, keyPair, err)
}

func (a *ServerController) getNewMldsa65(c *gin.Context) {
	keyPair, err := a.serverService.GetNewMldsa65()
	jsonObj(c, keyPair, err)
}

func (a *ServerController) getNewVlessEnc(c *gin.Context) {
	auths, err := a.serverService.GetNewVlessEnc()
	jsonObj(c, map[string]interface{}{"auths": auths}, err)
}
