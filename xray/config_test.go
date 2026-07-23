package xray

import (
	"testing"
	"x-ui/util/json_util"
)

func TestValidateOutboundConfigs(t *testing.T) {
	validHysteria := `{
        "protocol":"hysteria",
        "tag":"hy2",
        "settings":{"address":"example.com","port":443,"version":2},
        "streamSettings":{
            "network":"hysteria",
            "security":"tls",
            "tlsSettings":{"alpn":["h3"]},
            "hysteriaSettings":{"version":2,"udpIdleTimeout":60}
        }
    }`
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"all supported protocols", `[
            {"protocol":"vmess","tag":"vmess","settings":{}},
            {"protocol":"vless","tag":"vless","settings":{}},
            {"protocol":"trojan","tag":"trojan","settings":{}},
            {"protocol":"shadowsocks","tag":"ss","settings":{}},
            {"protocol":"socks","tag":"socks","settings":{}},
            {"protocol":"http","tag":"http","settings":{}},
            {"protocol":"wireguard","tag":"wg","settings":{}},
            ` + validHysteria + `,
            {"protocol":"freedom","settings":{}},
            {"protocol":"blackhole","tag":"blocked","settings":{}},
            {"protocol":"dns","tag":"dns-out","settings":{}},
            {"protocol":"loopback","tag":"loop","settings":{}}
        ]`, true},
		{"empty array", `[]`, true},
		{"not an array", `{}`, false},
		{"unsupported mtproto", `[{"protocol":"mtproto","settings":{}}]`, false},
		{"unsupported mixed", `[{"protocol":"mixed","settings":{}}]`, false},
		{"missing protocol", `[{"settings":{}}]`, false},
		{"wrong tag type", `[{"protocol":"freedom","tag":1,"settings":{}}]`, false},
		{"duplicate tags", `[{"protocol":"freedom","tag":"direct","settings":{}},{"protocol":"blackhole","tag":"direct","settings":{}}]`, false},
		{"wrong envelope types", `[{"protocol":"freedom","settings":[],"streamSettings":[],"mux":false,"proxySettings":"direct"}]`, false},
		{"hysteria v1", `[{"protocol":"hysteria","settings":{"version":1},"streamSettings":{"network":"hysteria","security":"tls","tlsSettings":{"alpn":["h3"]},"hysteriaSettings":{"version":2}}}]`, false},
		{"hysteria missing h3", `[{"protocol":"hysteria","settings":{"version":2},"streamSettings":{"network":"hysteria","security":"tls","tlsSettings":{"alpn":["h2"]},"hysteriaSettings":{"version":2}}}]`, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateOutboundConfigs(json_util.RawMessage(test.raw))
			if (err == nil) != test.want {
				t.Fatalf("ValidateOutboundConfigs() error = %v, want success=%v", err, test.want)
			}
		})
	}
}
