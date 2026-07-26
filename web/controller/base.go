package controller

import (
	"crypto/subtle"
	"net/http"
	"x-ui/database/model"
	"x-ui/web/service"
	"x-ui/web/session"

	"github.com/gin-gonic/gin"
)

// loginUserKey is where checkLogin stashes the resolved account for the rest of
// the request. Handlers read it through currentUser.
const loginUserKey = "login_user"

type BaseController struct {
	userService service.UserService
}

func (a *BaseController) checkLogin(c *gin.Context) {
	user := a.resolveLoginUser(c)
	if user == nil {
		if isAjax(c) {
			pureJsonMsg(c, false, "登录时效已过，请重新登录")
		} else {
			c.Redirect(http.StatusTemporaryRedirect, c.GetString("base_path"))
		}
		c.Abort()
		return
	}
	c.Set(loginUserKey, user)
	c.Next()
}

// resolveLoginUser turns the user id in the session cookie back into the
// current database row.
//
// The cookie is only signed, so it proves the server issued it but says nothing
// about whether it is still valid. Re-reading the row on every request is what
// lets a password change take effect immediately: the stored fingerprint no
// longer matches and every previously issued cookie stops authenticating.
func (a *BaseController) resolveLoginUser(c *gin.Context) *model.User {
	s := session.GetLoginSession(c)
	if s == nil {
		return nil
	}
	user, err := a.userService.GetUserById(s.UserId)
	if err != nil || user == nil {
		return nil
	}
	expected := user.CredentialFingerprint()
	if subtle.ConstantTimeCompare([]byte(s.Fingerprint), []byte(expected)) != 1 {
		return nil
	}
	return user
}

// CSRFTokenKey is the gin context key holding this session's CSRF token. html
// copies it into the template data so the page can echo it back on every
// state-changing request.
const CSRFTokenKey = "csrf_token"

// csrfHeader is where the browser sends the token back. A custom header cannot
// be set on a cross-origin request without the server opting in through CORS,
// which the panel never does.
const csrfHeader = "X-CSRF-Token"

// checkCSRF makes the session's CSRF token available to templates and rejects
// state-changing requests that do not echo it back.
func (a *BaseController) checkCSRF(c *gin.Context) {
	token, err := session.EnsureCSRFToken(c)
	if err != nil {
		pureJsonMsg(c, false, "会话初始化失败，请重新登录")
		c.Abort()
		return
	}
	c.Set(CSRFTokenKey, token)

	switch c.Request.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		// Safe methods render pages; they only need the token published.
		c.Next()
		return
	}

	if subtle.ConstantTimeCompare([]byte(c.GetHeader(csrfHeader)), []byte(token)) != 1 {
		pureJsonMsg(c, false, "CSRF 校验失败，请刷新页面后重试")
		c.Abort()
		return
	}
	c.Next()
}

// currentUser returns the account authenticated for this request, or nil if the
// handler is not behind checkLogin.
func currentUser(c *gin.Context) *model.User {
	value, exists := c.Get(loginUserKey)
	if !exists {
		return nil
	}
	user, _ := value.(*model.User)
	return user
}
