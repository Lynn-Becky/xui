package xray

import (
	"encoding/json"
	"testing"
	"x-ui/util/json_util"
)

func TestConfigFakeDNSUsesCoreFieldName(t *testing.T) {
	config := &Config{FakeDNS: json_util.RawMessage(`[{"ipPool":"198.18.0.0/15","poolSize":65535}]`)}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &root); err != nil {
		t.Fatalf("decode marshaled config: %v", err)
	}
	if _, ok := root["fakedns"]; !ok {
		t.Fatalf("marshaled config missing fakedns: %s", encoded)
	}
	if _, ok := root["fakeDns"]; ok {
		t.Fatalf("marshaled config used legacy fakeDns field: %s", encoded)
	}

	var decoded Config
	if err := json.Unmarshal([]byte(`{"fakeDns":[{"ipPool":"198.18.0.0/15","poolSize":65535}]}`), &decoded); err != nil {
		t.Fatalf("decode legacy fakeDns field: %v", err)
	}
	if len(decoded.FakeDNS) == 0 {
		t.Fatal("legacy fakeDns field should remain readable")
	}
}

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
