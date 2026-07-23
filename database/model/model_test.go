package model

import (
	"encoding/json"
	"testing"
)

const wireGuardTestKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func TestInboundValidateRealityTarget(t *testing.T) {
	base := Inbound{
		Port:     443,
		Protocol: VLESS,
		Settings: `{"clients":[],"decryption":"none","encryption":"none"}`,
		Sniffing: `{"enabled":true}`,
	}

	valid := base
	valid.StreamSettings = `{"network":"tcp","security":"reality","realitySettings":{"target":"example.com:443"}}`
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid REALITY inbound rejected: %v", err)
	}

	invalid := base
	invalid.StreamSettings = `{"network":"tcp","security":"reality","realitySettings":{"target":"example.com"}}`
	if err := invalid.Validate(); err == nil {
		t.Fatal("REALITY target without a port was accepted")
	}
}

func TestGenXrayInboundConfigStripsPanelOnlyFields(t *testing.T) {
	inbound := Inbound{
		Listen:   "",
		Port:     443,
		Protocol: VLESS,
		Settings: `{"clients":[{"id":"id","security":"auto"}],"decryption":"none","encryption":"none"}`,
		StreamSettings: `{
            "network":"xhttp",
            "security":"reality",
            "xhttpSettings":{"path":"/","sessionPlacement":"cookie","sessionKey":"sid","xmux":{"maxConnections":6},"scMinPostsIntervalMs":"50-100"},
            "realitySettings":{"target":"example.com:443","settings":{"publicKey":"public"}}
        }`,
		Sniffing: `{"enabled":true}`,
	}

	config := inbound.GenXrayInboundConfig()
	if string(config.Listen) != `"0.0.0.0"` {
		t.Fatalf("unexpected default listen: %s", config.Listen)
	}

	var settings map[string]interface{}
	if err := json.Unmarshal(config.Settings, &settings); err != nil {
		t.Fatal(err)
	}
	if _, exists := settings["encryption"]; exists {
		t.Fatal("panel-only VLESS encryption leaked into xray settings")
	}

	var stream map[string]interface{}
	if err := json.Unmarshal(config.StreamSettings, &stream); err != nil {
		t.Fatal(err)
	}
	xhttp := stream["xhttpSettings"].(map[string]interface{})
	if _, exists := xhttp["xmux"]; exists {
		t.Fatal("client-only XHTTP xmux leaked into inbound listener settings")
	}
	if _, exists := xhttp["scMinPostsIntervalMs"]; exists {
		t.Fatal("client-only XHTTP interval leaked into inbound listener settings")
	}
	if xhttp["sessionIDPlacement"] != "cookie" || xhttp["sessionIDKey"] != "sid" {
		t.Fatalf("legacy XHTTP session keys were not migrated: %#v", xhttp)
	}
	reality := stream["realitySettings"].(map[string]interface{})
	if _, exists := reality["settings"]; exists {
		t.Fatal("client-only REALITY settings leaked into xray settings")
	}
}

func TestSanitizeVMessClientSecurity(t *testing.T) {
	result := sanitizeInboundSettings(VMess, `{"clients":[{"id":"id","security":"auto","email":"a"}]}`)
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatal(err)
	}
	client := parsed["clients"].([]interface{})[0].(map[string]interface{})
	if _, exists := client["security"]; exists {
		t.Fatal("panel-only VMess security leaked into xray settings")
	}
	if client["email"] != "a" {
		t.Fatal("xray VMess client fields were removed with panel-only fields")
	}
}

func TestSanitizeLegacyXTLS(t *testing.T) {
	result := sanitizeInboundStreamSettings(`{"network":"tcp","security":"xtls","xtlsSettings":{"serverName":"example.com"}}`)
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed["security"] != "tls" {
		t.Fatalf("legacy XTLS was not migrated to TLS: %#v", parsed)
	}
	if _, exists := parsed["xtlsSettings"]; exists {
		t.Fatal("legacy xtlsSettings remained in runtime config")
	}
	if _, exists := parsed["tlsSettings"]; !exists {
		t.Fatal("legacy xtlsSettings were not moved to tlsSettings")
	}
}

func TestSanitizeShadowsocksSettingsForLatestCore(t *testing.T) {
	settings := `{"method":"2022-blake3-aes-256-gcm","clients":[{"email":"a","password":"p","method":"aes-256-gcm"}]}`
	result := sanitizeInboundSettings(Shadowsocks, settings)
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatal(err)
	}
	client := parsed["clients"].([]interface{})[0].(map[string]interface{})
	if _, exists := client["method"]; exists {
		t.Fatal("Shadowsocks 2022 client method must be omitted")
	}
}

func TestWireguardClientsBecomeRuntimePeers(t *testing.T) {
	inbound := Inbound{
		Port:           51820,
		Protocol:       WireGuard,
		Settings:       `{"secretKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","privateKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","clients":[{"email":"alice","enable":true,"publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","privateKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","preSharedKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","allowedIPs":["10.0.0.2/32"],"keepAlive":25,"limitIp":1},{"email":"bob","enable":false,"publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","allowedIPs":["10.0.0.3/32"]}]}`,
		StreamSettings: `{}`,
		Sniffing:       `{}`,
	}
	if err := inbound.Validate(); err != nil {
		t.Fatalf("valid wireguard inbound rejected: %v", err)
	}
	config := inbound.GenXrayInboundConfig()
	var settings map[string]interface{}
	if err := json.Unmarshal(config.Settings, &settings); err != nil {
		t.Fatal(err)
	}
	if _, exists := settings["clients"]; exists {
		t.Fatal("wireguard clients leaked into runtime settings")
	}
	if _, exists := settings["privateKey"]; exists {
		t.Fatal("panel-only wireguard privateKey leaked into runtime settings")
	}
	peers := settings["peers"].([]interface{})
	if len(peers) != 1 {
		t.Fatalf("peer count = %d, want 1", len(peers))
	}
	peer := peers[0].(map[string]interface{})
	if peer["publicKey"] != wireGuardTestKey || peer["email"] != "alice" {
		t.Fatalf("unexpected runtime peer: %#v", peer)
	}
	if _, exists := peer["privateKey"]; exists {
		t.Fatal("client privateKey leaked into runtime peer")
	}
	if _, exists := peer["limitIp"]; exists {
		t.Fatal("panel-only client field leaked into runtime peer")
	}
}

func TestValidateNewNativeProtocols(t *testing.T) {
	base := Inbound{Port: 443, Settings: `{}`, StreamSettings: `{}`, Sniffing: `{}`}
	for _, protocol := range []Protocol{Mixed, Tunnel} {
		inbound := base
		inbound.Protocol = protocol
		if err := inbound.Validate(); err != nil {
			t.Fatalf("%s rejected: %v", protocol, err)
		}
	}
	wg := base
	wg.Protocol = WireGuard
	wg.Settings = `{"secretKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","clients":[]}`
	if err := wg.Validate(); err != nil {
		t.Fatalf("wireguard rejected: %v", err)
	}
	base.Protocol = Protocol("socks")
	if err := base.Validate(); err == nil {
		t.Fatal("removed socks protocol was accepted")
	}
}

func TestValidateRejectsNullConfigObjects(t *testing.T) {
	base := Inbound{
		Port:           443,
		Protocol:       VMess,
		Settings:       `{}`,
		StreamSettings: `{}`,
		Sniffing:       `{}`,
	}
	tests := []struct {
		name           string
		settings       string
		streamSettings string
		sniffing       string
	}{
		{name: "null settings", settings: `null`, streamSettings: `{}`, sniffing: `{}`},
		{name: "null stream settings", settings: `{}`, streamSettings: `null`, sniffing: `{}`},
		{name: "null sniffing", settings: `{}`, streamSettings: `{}`, sniffing: `null`},
		{name: "null tls settings", settings: `{}`, streamSettings: `{"security":"tls","tlsSettings":null}`, sniffing: `{}`},
		{name: "missing tls settings", settings: `{}`, streamSettings: `{"security":"tls"}`, sniffing: `{}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inbound := base
			inbound.Settings = test.settings
			inbound.StreamSettings = test.streamSettings
			inbound.Sniffing = test.sniffing
			if err := inbound.Validate(); err == nil {
				t.Fatal("invalid config was accepted")
			}
		})
	}

	base.StreamSettings = `{"security":"tls","tlsSettings":{}}`
	if err := base.Validate(); err != nil {
		t.Fatalf("valid TLS object rejected: %v", err)
	}
}

func TestValidateWireGuardStrictSettings(t *testing.T) {
	base := Inbound{
		Port:           51820,
		Protocol:       WireGuard,
		StreamSettings: `{}`,
		Sniffing:       `{}`,
		Settings:       `{"secretKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","clients":[{"email":"alice","publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","allowedIPs":["10.0.0.2/32","fd00::2/128"]}]}`,
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid wireguard settings rejected: %v", err)
	}
	cases := []struct {
		name     string
		settings string
	}{
		{"missing server key", `{"clients":[]}`},
		{"invalid server key", `{"secretKey":"short","clients":[]}`},
		{"missing clients", `{"secretKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`},
		{"missing public key", `{"secretKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","clients":[{"email":"alice","allowedIPs":["10.0.0.2/32"]}]}`},
		{"empty allowed IPs", `{"secretKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","clients":[{"email":"alice","publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","allowedIPs":[]}]}`},
		{"invalid allowed IP", `{"secretKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","clients":[{"email":"alice","publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","allowedIPs":["not-an-ip"]}]}`},
		{"invalid pre-shared key", `{"secretKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","clients":[{"email":"alice","publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","preSharedKey":"bad","allowedIPs":["10.0.0.2"]}]}`},
	}
	for _, test := range cases {
		inbound := base
		inbound.Settings = test.settings
		if err := inbound.Validate(); err == nil {
			t.Fatalf("%s was accepted", test.name)
		}
	}
}

func TestValidateMixedPasswordAllowsEmptyAccountsLike3xUI(t *testing.T) {
	base := Inbound{Port: 1080, Protocol: Mixed, StreamSettings: `{}`, Sniffing: `{}`}
	for _, settings := range []string{
		`{"auth":"password"}`,
		`{"auth":"password","accounts":[]}`,
		`{"auth":"noauth"}`,
	} {
		base.Settings = settings
		if err := base.Validate(); err != nil {
			t.Fatalf("mixed settings %s rejected: %v", settings, err)
		}
	}
	base.Settings = `{"auth":"password","accounts":[{"user":"","pass":"x"}]}`
	if err := base.Validate(); err == nil {
		t.Fatal("mixed password account with empty user was accepted")
	}
}

func TestValidateTunnelRewritePortBounds(t *testing.T) {
	base := Inbound{Port: 1234, Protocol: Tunnel, StreamSettings: `{}`, Sniffing: `{}`}
	for _, settings := range []string{
		`{"rewritePort":1,"allowedNetwork":"tcp,udp","portMap":{}}`,
		`{"rewritePort":65535,"allowedNetwork":"udp","portMap":{"80":"127.0.0.1:8080"}}`,
	} {
		base.Settings = settings
		if err := base.Validate(); err != nil {
			t.Fatalf("valid tunnel settings %s rejected: %v", settings, err)
		}
	}
	for _, settings := range []string{`{"rewritePort":0}`, `{"rewritePort":65536}`, `{"rewritePort":1.5}`} {
		base.Settings = settings
		if err := base.Validate(); err == nil {
			t.Fatalf("invalid tunnel settings %s accepted", settings)
		}
	}
}

func TestValidateHysteria2(t *testing.T) {
	inbound := Inbound{
		Port:           443,
		Protocol:       Hysteria,
		Settings:       `{"version":2,"clients":[{"auth":"token","email":"alice"}]}`,
		StreamSettings: `{"network":"hysteria","security":"tls","tlsSettings":{"alpn":["h3"]},"hysteriaSettings":{"version":2,"udpIdleTimeout":60}}`,
		Sniffing:       `{}`,
	}
	if err := inbound.Validate(); err != nil {
		t.Fatalf("valid Hysteria2 inbound rejected: %v", err)
	}
	inbound.StreamSettings = `{"network":"hysteria","security":"tls","tlsSettings":{"alpn":["h3"]},"hysteriaSettings":{"version":2,"udpIdleTimeout":601}}`
	if err := inbound.Validate(); err == nil {
		t.Fatal("Hysteria UDP timeout above core limit was accepted")
	}
	inbound.StreamSettings = `{"network":"tcp","security":"tls","tlsSettings":{"alpn":["h3"]},"hysteriaSettings":{"version":2,"udpIdleTimeout":60}}`
	if err := inbound.Validate(); err == nil {
		t.Fatal("Hysteria non-Hysteria transport was accepted")
	}
	inbound.StreamSettings = `{"network":"hysteria","security":"tls","tlsSettings":{"alpn":["h3"]},"hysteriaSettings":{"version":2,"udpIdleTimeout":60}}`
	inbound.Settings = `{"version":1,"clients":[{"auth":"token","email":"alice"}]}`
	if err := inbound.Validate(); err == nil {
		t.Fatal("Hysteria v1 settings were accepted for a Hysteria2 inbound")
	}
	inbound.Settings = `{"clients":[{"auth":"token","email":"alice"}]}`
	if err := inbound.Validate(); err == nil {
		t.Fatal("Hysteria settings without explicit v2 version were accepted")
	}
	inbound.Settings = `{"version":2,"clients":[{"auth":"token","email":"alice"}]}`
	inbound.StreamSettings = `{"network":"hysteria","security":"tls","tlsSettings":{"alpn":["h2"]},"hysteriaSettings":{"version":2,"udpIdleTimeout":60}}`
	if err := inbound.Validate(); err == nil {
		t.Fatal("Hysteria TLS settings without h3 ALPN were accepted")
	}
}
