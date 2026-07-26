package controller

import (
	"fmt"
	"net/http"
	"strings"
	"time"
	"x-ui/logger"
	"x-ui/util/limiter"
	"x-ui/web/job"
	"x-ui/web/session"

	"github.com/gin-gonic/gin"
)

type LoginForm struct {
	Username string `json:"username" form:"username"`
	Password string `json:"password" form:"password"`
}

var (
	// Throttling by source address is the primary brute-force defence.
	// getRemoteIp only honours X-Forwarded-For from configured trusted proxies,
	// so this key cannot be rotated at will by the client.
	loginIPLimiter = limiter.New(5, 30*time.Second, 15*time.Minute, time.Hour)

	// Throttling by account catches an attack distributed across many source
	// addresses. The threshold is deliberately far higher than the per-IP one:
	// a low value would let anyone lock the real administrator out simply by
	// guessing their username.
	loginUserLimiter = limiter.New(50, time.Minute, 15*time.Minute, time.Hour)
)

type IndexController struct {
	BaseController
}

func NewIndexController(g *gin.RouterGroup) *IndexController {
	a := &IndexController{}
	a.initRouter(g)
	return a
}

func (a *IndexController) initRouter(g *gin.RouterGroup) {
	g.GET("/", a.index)
	g.POST("/login", a.login)
	// Logout is a POST and carries the CSRF token like every other state
	// change; the UI sends it through the shared axios default header.
	g.POST("/logout", a.checkCSRF, a.logout)
}

func (a *IndexController) index(c *gin.Context) {
	// Resolve the session the same way checkLogin does rather than only
	// checking that a cookie exists: a cookie that no longer authenticates
	// would otherwise bounce between here and /xui/ forever.
	if a.resolveLoginUser(c) != nil {
		c.Redirect(http.StatusTemporaryRedirect, "xui/")
		return
	}
	html(c, "login.html", "登录", nil)
}

func (a *IndexController) login(c *gin.Context) {
	var form LoginForm
	err := c.ShouldBind(&form)
	if err != nil {
		pureJsonMsg(c, false, "数据格式错误")
		return
	}
	if form.Username == "" {
		pureJsonMsg(c, false, "请输入用户名")
		return
	}
	if form.Password == "" {
		pureJsonMsg(c, false, "请输入密码")
		return
	}

	remoteIp := getRemoteIp(c)
	ipKey := "ip:" + remoteIp
	userKey := "user:" + strings.ToLower(form.Username)

	// Check before verifying the credential so a locked-out client cannot keep
	// spending a bcrypt comparison per request.
	for _, check := range []struct {
		limiter *limiter.Limiter
		key     string
	}{
		{loginIPLimiter, ipKey},
		{loginUserLimiter, userKey},
	} {
		if retryAfter, ok := check.limiter.Allow(check.key); !ok {
			logger.Warningf("login throttled for %s (retry in %v)", remoteIp, retryAfter.Truncate(time.Second))
			// Deliberately does not reveal which limit was hit.
			pureJsonMsg(c, false, fmt.Sprintf("尝试次数过多，请在 %d 秒后重试", int(retryAfter.Seconds())+1))
			return
		}
	}

	user := a.userService.CheckUser(form.Username, form.Password)
	timeStr := time.Now().Format("2006-01-02 15:04:05")
	if user == nil {
		loginIPLimiter.Fail(ipKey)
		loginUserLimiter.Fail(userKey)
		job.NewStatsNotifyJob().UserLoginNotify(form.Username, remoteIp, timeStr, 0)
		logger.Infof("login failed for username %q from %s", form.Username, remoteIp)
		pureJsonMsg(c, false, "用户名或密码错误")
		return
	}
	loginIPLimiter.Reset(ipKey)
	loginUserLimiter.Reset(userKey)
	logger.Infof("%s login success, ip address: %s", form.Username, remoteIp)
	job.NewStatsNotifyJob().UserLoginNotify(form.Username, remoteIp, timeStr, 1)

	// Only the account id and a credential fingerprint go into the cookie.
	if err := session.SetLoginSession(c, user.Id, user.CredentialFingerprint()); err != nil {
		logger.Warning("set login session failed:", err)
		pureJsonMsg(c, false, "登录失败")
		return
	}
	logger.Info("user", user.Id, "login success")
	jsonMsg(c, "登录", nil)
}

func (a *IndexController) logout(c *gin.Context) {
	if s := session.GetLoginSession(c); s != nil {
		logger.Info("user", s.UserId, "logout")
	}
	session.ClearSession(c)
	// The UI calls this with axios and performs the redirect itself.
	jsonMsg(c, "登出", nil)
}
