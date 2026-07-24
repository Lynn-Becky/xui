package model

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"x-ui/util/json_util"
	"x-ui/xray"
)

type Protocol string

const (
	VMess       Protocol = "vmess"
	VLESS       Protocol = "vless"
	Tunnel      Protocol = "tunnel"
	Http        Protocol = "http"
	Trojan      Protocol = "trojan"
	Shadowsocks Protocol = "shadowsocks"
	Mixed       Protocol = "mixed"
	WireGuard   Protocol = "wireguard"
	Hysteria    Protocol = "hysteria"
)

type User struct {
	Id       int    `json:"id" gorm:"primaryKey;autoIncrement"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Inbound struct {
	Id         int    `json:"id" form:"id" gorm:"primaryKey;autoIncrement"`
	UserId     int    `json:"-"`
	Up         int64  `json:"up" form:"up"`
	Down       int64  `json:"down" form:"down"`
	Total      int64  `json:"total" form:"total"`
	Remark     string `json:"remark" form:"remark"`
	Enable     bool   `json:"enable" form:"enable"`
	ExpiryTime int64  `json:"expiryTime" form:"expiryTime"`

	// config part
	Listen         string   `json:"listen" form:"listen"`
	Port           int      `json:"port" form:"port" gorm:"unique"`
	Protocol       Protocol `json:"protocol" form:"protocol"`
	Settings       string   `json:"settings" form:"settings"`
	StreamSettings string   `json:"streamSettings" form:"streamSettings"`
	Tag            string   `json:"tag" form:"tag" gorm:"unique"`
	Sniffing       string   `json:"sniffing" form:"sniffing"`
}

func (i *Inbound) GenXrayInboundConfig() *xray.InboundConfig {
	listen := i.Listen
	if listen == "" {
		listen = "0.0.0.0"
	}
	listen = fmt.Sprintf("\"%v\"", listen)
	settings := sanitizeInboundSettings(i.Protocol, i.Settings)
	streamSettings := sanitizeInboundStreamSettings(i.StreamSettings)
	return &xray.InboundConfig{
		Listen:         json_util.RawMessage(listen),
		Port:           i.Port,
		Protocol:       string(i.Protocol),
		Settings:       json_util.RawMessage(settings),
		StreamSettings: json_util.RawMessage(streamSettings),
		Tag:            i.Tag,
		Sniffing:       json_util.RawMessage(i.Sniffing),
	}
}

func (i *Inbound) Validate() error {
	if i.Port < 1 || i.Port > 65535 {
		return fmt.Errorf("invalid inbound port: %d", i.Port)
	}
	switch i.Protocol {
	case VMess, VLESS, Tunnel, Http, Trojan, Shadowsocks, Mixed, WireGuard, Hysteria:
	default:
		return fmt.Errorf("unsupported inbound protocol: %s", i.Protocol)
	}

	objects := make(map[string]map[string]interface{}, 3)
	for name, raw := range map[string]string{
		"settings":       i.Settings,
		"streamSettings": i.StreamSettings,
		"sniffing":       i.Sniffing,
	} {
		if strings.TrimSpace(raw) == "" {
			return fmt.Errorf("%s must be a JSON object", name)
		}
		var value interface{}
		if err := json.Unmarshal([]byte(raw), &value); err != nil {
			return fmt.Errorf("invalid %s: %w", name, err)
		}
		object, ok := value.(map[string]interface{})
		if !ok || object == nil {
			return fmt.Errorf("%s must be a JSON object", name)
		}
		objects[name] = object
	}

	settings := objects["settings"]
	stream := objects["streamSettings"]
	if stream["security"] == "xtls" {
		return fmt.Errorf("XTLS security is obsolete; use TLS with xtls-rprx-vision flow")
	}
	if stream["security"] == "tls" {
		if tlsSettings, ok := stream["tlsSettings"].(map[string]interface{}); !ok || tlsSettings == nil {
			return fmt.Errorf("tlsSettings is required when TLS is enabled")
		}
	}
	if stream["security"] == "reality" {
		reality, ok := stream["realitySettings"].(map[string]interface{})
		if !ok {
			return fmt.Errorf("realitySettings is required when REALITY is enabled")
		}
		target, _ := reality["target"].(string)
		if !validRealityTarget(target) {
			return fmt.Errorf("REALITY target must include a valid port")
		}
	}
	if i.Protocol == Mixed {
		if err := validateMixedSettings(settings); err != nil {
			return err
		}
	}
	if i.Protocol == Tunnel {
		if err := validateTunnelSettings(settings); err != nil {
			return err
		}
	}
	if i.Protocol == WireGuard {
		if err := validateWireGuardSettings(settings); err != nil {
			return err
		}
	}
	if i.Protocol == Hysteria {
		if err := validateHysteriaSettings(settings, stream); err != nil {
			return err
		}
	}
	return nil
}

func validateMixedSettings(settings map[string]interface{}) error {
	if auth, exists := settings["auth"]; exists {
		authValue, ok := auth.(string)
		if !ok || (authValue != "password" && authValue != "noauth") {
			return fmt.Errorf("mixed auth must be password or noauth")
		}
	}
	if udp, exists := settings["udp"]; exists {
		if _, ok := udp.(bool); !ok {
			return fmt.Errorf("mixed udp must be a boolean")
		}
	}
	if ip, exists := settings["ip"]; exists {
		if _, ok := ip.(string); !ok {
			return fmt.Errorf("mixed ip must be a string")
		}
	}
	if accounts, exists := settings["accounts"]; exists {
		items, ok := accounts.([]interface{})
		if !ok {
			return fmt.Errorf("mixed accounts must be an array")
		}
		for _, item := range items {
			account, ok := item.(map[string]interface{})
			if !ok {
				return fmt.Errorf("mixed account must be an object")
			}
			user, userOK := account["user"].(string)
			pass, passOK := account["pass"].(string)
			if !userOK || strings.TrimSpace(user) == "" || !passOK || strings.TrimSpace(pass) == "" {
				return fmt.Errorf("mixed accounts require user and pass")
			}
		}
	}
	return nil
}

func validateTunnelSettings(settings map[string]interface{}) error {
	for _, key := range []string{"rewriteAddress"} {
		if value, exists := settings[key]; exists {
			if _, ok := value.(string); !ok {
				return fmt.Errorf("tunnel %s must be a string", key)
			}
		}
	}
	if port, exists := settings["rewritePort"]; exists {
		portNumber, ok := jsonNumberToInt(port)
		if !ok || portNumber < 1 || portNumber > 65535 {
			return fmt.Errorf("tunnel rewritePort must be between 1 and 65535")
		}
	}
	if network, exists := settings["allowedNetwork"]; exists {
		networkValue, ok := network.(string)
		if !ok || (networkValue != "tcp" && networkValue != "udp" && networkValue != "tcp,udp") {
			return fmt.Errorf("tunnel allowedNetwork must be tcp, udp, or tcp,udp")
		}
	}
	if followRedirect, exists := settings["followRedirect"]; exists {
		if _, ok := followRedirect.(bool); !ok {
			return fmt.Errorf("tunnel followRedirect must be a boolean")
		}
	}
	if portMap, exists := settings["portMap"]; exists {
		entries, ok := portMap.(map[string]interface{})
		if !ok {
			return fmt.Errorf("tunnel portMap must be an object")
		}
		for name, destination := range entries {
			if _, ok := destination.(string); !ok || strings.TrimSpace(name) == "" {
				return fmt.Errorf("tunnel portMap entries must be non-empty string pairs")
			}
		}
	}
	return nil
}

func validateWireGuardSettings(settings map[string]interface{}) error {
	secretKey, ok := settings["secretKey"].(string)
	if !ok || !validWireGuardKey(secretKey) {
		return fmt.Errorf("wireguard secretKey must be a valid 32-byte key")
	}
	clients, ok := settings["clients"].([]interface{})
	if !ok {
		return fmt.Errorf("wireguard clients must be an array")
	}
	for index, rawClient := range clients {
		client, ok := rawClient.(map[string]interface{})
		if !ok {
			return fmt.Errorf("wireguard client %d must be an object", index)
		}
		email, ok := client["email"].(string)
		if !ok || strings.TrimSpace(email) == "" {
			return fmt.Errorf("wireguard client %d requires email", index)
		}
		publicKey, ok := client["publicKey"].(string)
		if !ok || !validWireGuardKey(publicKey) {
			return fmt.Errorf("wireguard client %d requires a valid publicKey", index)
		}
		allowedIPs, ok := client["allowedIPs"].([]interface{})
		if !ok || len(allowedIPs) == 0 {
			return fmt.Errorf("wireguard client %d requires allowedIPs", index)
		}
		for _, rawIP := range allowedIPs {
			value, ok := rawIP.(string)
			if !ok || !validWireGuardAllowedIP(value) {
				return fmt.Errorf("wireguard client %d has invalid allowedIPs entry", index)
			}
		}
		for _, key := range []string{"privateKey", "preSharedKey"} {
			if value, exists := client[key]; exists {
				keyValue, ok := value.(string)
				if !ok || !validWireGuardKey(keyValue) {
					return fmt.Errorf("wireguard client %d has invalid %s", index, key)
				}
			}
		}
		if enabled, exists := client["enable"]; exists {
			if _, ok := enabled.(bool); !ok {
				return fmt.Errorf("wireguard client %d enable must be a boolean", index)
			}
		}
		if keepAlive, exists := client["keepAlive"]; exists {
			value, ok := jsonNumberToInt(keepAlive)
			if !ok || value < 0 {
				return fmt.Errorf("wireguard client %d keepAlive must be a non-negative integer", index)
			}
		}
	}
	if mtu, exists := settings["mtu"]; exists {
		value, ok := jsonNumberToInt(mtu)
		if !ok || value < 1 {
			return fmt.Errorf("wireguard mtu must be a positive integer")
		}
	}
	if dns, exists := settings["dns"]; exists {
		if _, ok := dns.(string); !ok {
			return fmt.Errorf("wireguard dns must be a string")
		}
	}
	if peers, exists := settings["peers"]; exists {
		if _, ok := peers.([]interface{}); !ok {
			return fmt.Errorf("wireguard peers must be an array")
		}
	}
	if noKernelTun, exists := settings["noKernelTun"]; exists {
		if _, ok := noKernelTun.(bool); !ok {
			return fmt.Errorf("wireguard noKernelTun must be a boolean")
		}
	}
	if domainStrategy, exists := settings["domainStrategy"]; exists {
		value, ok := domainStrategy.(string)
		if !ok || !validWireGuardDomainStrategy(value) {
			return fmt.Errorf("wireguard domainStrategy is invalid")
		}
	}
	return nil
}

func validWireGuardKey(key string) bool {
	if key == "" || key != strings.TrimSpace(key) {
		return false
	}
	if len(key) == 64 {
		decoded, err := hex.DecodeString(key)
		return err == nil && len(decoded) == 32
	}
	trimmed := strings.TrimRight(key, "=")
	for _, encoding := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		decoded, err := encoding.DecodeString(trimmed)
		if err == nil && len(decoded) == 32 {
			return true
		}
	}
	return false
}

func validWireGuardAllowedIP(value string) bool {
	if value == "" || value != strings.TrimSpace(value) {
		return false
	}
	if net.ParseIP(value) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(value)
	return err == nil
}

func validWireGuardDomainStrategy(value string) bool {
	switch value {
	case "ForceIP", "ForceIPv4", "ForceIPv4v6", "ForceIPv6", "ForceIPv6v4":
		return true
	default:
		return false
	}
}

func validateHysteriaSettings(settings, stream map[string]interface{}) error {
	version, ok := jsonNumberToInt(settings["version"])
	if !ok || version != 2 {
		return fmt.Errorf("hysteria settings version must be 2")
	}
	clients, exists := settings["clients"]
	if exists {
		items, ok := clients.([]interface{})
		if !ok {
			return fmt.Errorf("hysteria clients must be an array")
		}
		for _, item := range items {
			client, ok := item.(map[string]interface{})
			if !ok {
				return fmt.Errorf("hysteria client must be an object")
			}
			auth, authOK := client["auth"].(string)
			email, emailOK := client["email"].(string)
			if !authOK || strings.TrimSpace(auth) == "" || !emailOK || strings.TrimSpace(email) == "" {
				return fmt.Errorf("hysteria clients require auth and email")
			}
		}
	}
	if stream["network"] != "hysteria" || stream["security"] != "tls" {
		return fmt.Errorf("hysteria requires hysteria network and TLS security")
	}
	tlsSettings, ok := stream["tlsSettings"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("hysteria TLS settings are required")
	}
	alpn, ok := tlsSettings["alpn"].([]interface{})
	if !ok || !hasALPN(alpn, "h3") {
		return fmt.Errorf("hysteria TLS ALPN must include h3")
	}
	hysteriaSettings, ok := stream["hysteriaSettings"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("hysteriaSettings is required")
	}
	version, ok = jsonNumberToInt(hysteriaSettings["version"])
	if !ok || version != 2 {
		return fmt.Errorf("hysteriaSettings version must be 2")
	}
	udpIdleTimeout, ok := jsonNumberToInt(hysteriaSettings["udpIdleTimeout"])
	if !ok || udpIdleTimeout < 2 || udpIdleTimeout > 600 {
		return fmt.Errorf("hysteria udpIdleTimeout must be between 2 and 600")
	}
	return nil
}

func hasALPN(values []interface{}, expected string) bool {
	for _, value := range values {
		if alpn, ok := value.(string); ok && alpn == expected {
			return true
		}
	}
	return false
}

func jsonNumberToInt(value interface{}) (int, bool) {
	number, ok := value.(float64)
	if !ok || number != float64(int(number)) {
		return 0, false
	}
	return int(number), true
}

func validRealityTarget(target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	if strings.HasPrefix(target, "/") || strings.HasPrefix(target, "@") {
		return true
	}
	if !strings.Contains(target, ":") {
		port, err := strconv.Atoi(target)
		return err == nil && port > 0 && port <= 65535
	}
	lastColon := strings.LastIndex(target, ":")
	if lastColon <= 0 || lastColon == len(target)-1 {
		return false
	}
	port, err := strconv.Atoi(target[lastColon+1:])
	return err == nil && port > 0 && port <= 65535
}

// sanitizeInboundSettings removes panel-only fields before runtime configuration.
func sanitizeInboundSettings(protocol Protocol, settings string) string {
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(settings), &parsed); err != nil {
		return settings
	}

	changed := false
	switch protocol {
	case VLESS:
		if _, ok := parsed["encryption"]; ok {
			delete(parsed, "encryption")
			changed = true
		}
	case VMess:
		clients, _ := parsed["clients"].([]interface{})
		for _, client := range clients {
			if values, ok := client.(map[string]interface{}); ok {
				if _, exists := values["security"]; exists {
					delete(values, "security")
					changed = true
				}
			}
		}
	case Shadowsocks:
		method, _ := parsed["method"].(string)
		clients, _ := parsed["clients"].([]interface{})
		is2022 := strings.HasPrefix(method, "2022-blake3-")
		for _, client := range clients {
			values, ok := client.(map[string]interface{})
			if !ok {
				continue
			}
			if is2022 {
				if _, exists := values["method"]; exists {
					delete(values, "method")
					changed = true
				}
			} else if method != "" && values["method"] != method {
				values["method"] = method
				changed = true
			}
		}
	case Trojan:
		if clients, ok := parsed["clients"].([]interface{}); ok {
			for _, client := range clients {
				if values, ok := client.(map[string]interface{}); ok {
					if _, exists := values["flow"]; exists {
						delete(values, "flow")
						changed = true
					}
				}
			}
		}
	case WireGuard:
		if converted, ok := WireguardClientsToPeers(settings); ok {
			return converted
		}
	}

	if !changed {
		return settings
	}
	result, err := json.Marshal(parsed)
	if err != nil {
		return settings
	}
	return string(result)
}

// WireguardClientsToPeers converts the panel's client records to the peer
// shape expected by Xray's native WireGuard inbound. Client private keys and
// panel-only bookkeeping are intentionally never emitted to Xray.
func WireguardClientsToPeers(settings string) (string, bool) {
	if strings.TrimSpace(settings) == "" {
		return settings, false
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(settings), &parsed); err != nil {
		return settings, false
	}
	clients, ok := parsed["clients"].([]interface{})
	if !ok {
		return settings, false
	}
	peers := make([]interface{}, 0, len(clients))
	for _, item := range clients {
		client, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if enabled, exists := client["enable"].(bool); exists && !enabled {
			continue
		}
		peers = append(peers, wireguardPeerFromClient(client))
	}
	delete(parsed, "clients")
	delete(parsed, "privateKey")
	parsed["peers"] = peers
	result, err := json.Marshal(parsed)
	if err != nil {
		return settings, false
	}
	return string(result), true
}

func wireguardPeerFromClient(client map[string]interface{}) map[string]interface{} {
	peer := map[string]interface{}{"level": 0}
	if email, ok := client["email"].(string); ok && email != "" {
		peer["email"] = email
	}
	for _, key := range []string{"publicKey", "preSharedKey", "allowedIPs", "keepAlive"} {
		if value, exists := client[key]; exists {
			peer[key] = value
		}
	}
	return peer
}

func sanitizeInboundStreamSettings(streamSettings string) string {
	if strings.TrimSpace(streamSettings) == "" {
		return streamSettings
	}
	var stream map[string]interface{}
	if err := json.Unmarshal([]byte(streamSettings), &stream); err != nil {
		return streamSettings
	}
	changed := false
	for _, key := range []string{"tlsSettings", "realitySettings"} {
		if security, ok := stream[key].(map[string]interface{}); ok {
			if _, exists := security["settings"]; exists {
				delete(security, "settings")
				changed = true
			}
		}
	}
	if xhttp, ok := stream["xhttpSettings"].(map[string]interface{}); ok {
		for _, key := range []string{"xmux", "downloadSettings", "scMinPostsIntervalMs", "uplinkChunkSize", "noGRPCHeader", "enableXmux"} {
			if _, exists := xhttp[key]; exists {
				delete(xhttp, key)
				changed = true
			}
		}
	}
	if !changed {
		return streamSettings
	}
	result, err := json.Marshal(stream)
	if err != nil {
		return streamSettings
	}
	return string(result)
}

type Setting struct {
	Id    int    `json:"id" form:"id" gorm:"primaryKey;autoIncrement"`
	Key   string `json:"key" form:"key"`
	Value string `json:"value" form:"value"`
}
