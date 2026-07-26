package controller

import (
	"net"
	"net/http"
	"x-ui/config"
	"x-ui/logger"
	"x-ui/web/entity"

	"github.com/gin-gonic/gin"
)

func getUriId(c *gin.Context) int64 {
	s := struct {
		Id int64 `uri:"id"`
	}{}

	_ = c.BindUri(&s)
	return s.Id
}

// getRemoteIp returns the client address for logging and login throttling.
//
// It delegates to gin, which only consults X-Forwarded-For when the immediate
// peer is a configured trusted proxy (see config.GetTrustedProxies). Reading the
// header unconditionally, as this used to, let any client choose its own
// apparent address — which both forges the audit log and would let an attacker
// sidestep per-IP throttling by rotating the header.
func getRemoteIp(c *gin.Context) string {
	if ip := c.ClientIP(); ip != "" {
		return ip
	}
	ip, _, err := net.SplitHostPort(c.Request.RemoteAddr)
	if err != nil {
		return c.Request.RemoteAddr
	}
	return ip
}

func jsonMsg(c *gin.Context, msg string, err error) {
	jsonMsgObj(c, msg, nil, err)
}

func jsonObj(c *gin.Context, obj interface{}, err error) {
	jsonMsgObj(c, "", obj, err)
}

func jsonMsgObj(c *gin.Context, msg string, obj interface{}, err error) {
	m := entity.Msg{
		Obj: obj,
	}
	if err == nil {
		m.Success = true
		if msg != "" {
			m.Msg = msg + "成功"
		}
	} else {
		m.Success = false
		m.Msg = msg + "失败: " + err.Error()
		logger.Warning(msg+"失败: ", err)
	}
	c.JSON(http.StatusOK, m)
}

func pureJsonMsg(c *gin.Context, success bool, msg string) {
	if success {
		c.JSON(http.StatusOK, entity.Msg{
			Success: true,
			Msg:     msg,
		})
	} else {
		c.JSON(http.StatusOK, entity.Msg{
			Success: false,
			Msg:     msg,
		})
	}
}

// LocaleKey is the gin context key holding the locale resolved for the request.
// html copies it into the template data because html/template functions get no
// request context, so the renderer selects the per-locale template set from the
// data instead.
const LocaleKey = "locale"

func html(c *gin.Context, name string, title string, data gin.H) {
	if data == nil {
		data = gin.H{}
	}
	data[LocaleKey] = c.GetString(LocaleKey)
	data[CSRFTokenKey] = c.GetString(CSRFTokenKey)
	data["title"] = title
	// Deliberately not exposing the request URI to templates: it is
	// attacker-controlled and Go's HTML escaping does not protect a value that
	// Vue later compiles as a v-bind expression. Templates use
	// location.pathname instead.
	data["base_path"] = c.GetString("base_path")
	c.HTML(http.StatusOK, name, getContext(data))
}

func getContext(h gin.H) gin.H {
	a := gin.H{
		"cur_ver": config.GetVersion(),
	}
	if h != nil {
		for key, value := range h {
			a[key] = value
		}
	}
	return a
}

func isAjax(c *gin.Context) bool {
	return c.GetHeader("X-Requested-With") == "XMLHttpRequest"
}
