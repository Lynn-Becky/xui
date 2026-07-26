package web

import (
	"strings"

	"github.com/gin-gonic/gin"
)

// contentSecurityPolicy is deliberately not a strict policy.
//
// The panel ships Vue 2's full build and mounts with el: '#app', so templates
// are compiled in the browser with new Function — that requires 'unsafe-eval',
// and the pages also carry inline <script> blocks, which requires
// 'unsafe-inline'. Those two make CSP useless as a way to stop script execution.
//
// What it still buys, and the reason it is worth setting:
//   - frame-ancestors 'none' blocks clickjacking (several controls, such as the
//     per-inbound enable switch, act on a single click with no confirmation).
//   - connect-src 'self' and form-action 'self' stop a script that does run from
//     shipping the panel's data — inbound secrets, the database backup — to an
//     attacker-controlled host.
//   - object-src 'none' and base-uri 'none' remove two common escalation paths.
//
// Tightening script-src means moving the inline blocks out and switching to
// Vue's runtime-only build with precompiled templates.
var contentSecurityPolicy = strings.Join([]string{
	"default-src 'self'",
	"script-src 'self' 'unsafe-inline' 'unsafe-eval'",
	"style-src 'self' 'unsafe-inline'",
	"img-src 'self' data:",
	"font-src 'self' data:",
	"connect-src 'self'",
	"frame-ancestors 'none'",
	"base-uri 'none'",
	"form-action 'self'",
	"object-src 'none'",
}, "; ")

// securityHeaders sets the response headers that apply to every panel response.
// hsts is only sent when the panel terminates TLS itself: advertising it over
// plain HTTP would pin browsers to an HTTPS endpoint that does not exist.
func securityHeaders(directHTTPS bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.Writer.Header()
		header.Set("X-Frame-Options", "DENY")
		header.Set("Content-Security-Policy", contentSecurityPolicy)
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("Referrer-Policy", "same-origin")
		if directHTTPS {
			header.Set("Strict-Transport-Security", "max-age=31536000")
		}
		c.Next()
	}
}
