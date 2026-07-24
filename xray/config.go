package xray

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"x-ui/util/json_util"
)

type Config struct {
	LogConfig       json_util.RawMessage `json:"log"`
	RouterConfig    json_util.RawMessage `json:"routing"`
	DNSConfig       json_util.RawMessage `json:"dns"`
	InboundConfigs  []InboundConfig      `json:"inbounds"`
	OutboundConfigs json_util.RawMessage `json:"outbounds"`
	Transport       json_util.RawMessage `json:"transport"`
	Policy          json_util.RawMessage `json:"policy"`
	API             json_util.RawMessage `json:"api"`
	Stats           json_util.RawMessage `json:"stats"`
	Reverse         json_util.RawMessage `json:"reverse"`
	FakeDNS         json_util.RawMessage `json:"fakedns"`
}

// ValidateOutboundConfigs performs deliberately shallow validation of the
// user-authored outbounds section. The panel persists this section as raw Xray
// JSON, so this validates stable envelope fields without rejecting legitimate
// newer core fields that this panel version does not yet know about.
func (c *Config) ValidateOutboundConfigs() error {
	return ValidateOutboundConfigs(c.OutboundConfigs)
}

// ValidateOutboundConfigs validates the Xray outbound envelope used by the
// template editor. Only current, user-configurable Xray protocol names are
// accepted here; inbound-only and non-Xray sidecar protocols are excluded.
func ValidateOutboundConfigs(raw json_util.RawMessage) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return fmt.Errorf("outbounds must be a JSON array")
	}
	var outbounds []json.RawMessage
	if err := json.Unmarshal(trimmed, &outbounds); err != nil {
		return fmt.Errorf("outbounds must be a JSON array: %w", err)
	}

	tags := make(map[string]struct{}, len(outbounds))
	for index, rawOutbound := range outbounds {
		outbound, err := decodeJSONObject(rawOutbound, "outbound")
		if err != nil {
			return fmt.Errorf("outbound %d: %w", index, err)
		}
		protocol, err := requiredJSONString(outbound, "protocol")
		if err != nil {
			return fmt.Errorf("outbound %d: %w", index, err)
		}
		if !isSupportedOutboundProtocol(protocol) {
			return fmt.Errorf("outbound %d uses unsupported protocol: %s", index, protocol)
		}
		if tag, exists, err := optionalJSONString(outbound, "tag"); err != nil {
			return fmt.Errorf("outbound %d: %w", index, err)
		} else if exists && tag != "" {
			if _, duplicate := tags[tag]; duplicate {
				return fmt.Errorf("outbound %d has duplicate tag: %s", index, tag)
			}
			tags[tag] = struct{}{}
		}
		for _, field := range []string{"settings", "streamSettings", "mux", "proxySettings"} {
			if rawField, exists := outbound[field]; exists {
				if _, err := decodeJSONObject(rawField, field); err != nil {
					return fmt.Errorf("outbound %d: %w", index, err)
				}
			}
		}
		if _, _, err := optionalJSONString(outbound, "sendThrough"); err != nil {
			return fmt.Errorf("outbound %d: %w", index, err)
		}
		if protocol == "hysteria" {
			if err := validateHysteria2Outbound(outbound); err != nil {
				return fmt.Errorf("outbound %d: %w", index, err)
			}
		}
	}
	return nil
}

func decodeJSONObject(raw json.RawMessage, name string) (map[string]json.RawMessage, error) {
	if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, fmt.Errorf("%s must be a JSON object", name)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		if err != nil {
			return nil, fmt.Errorf("%s must be a JSON object: %w", name, err)
		}
		return nil, fmt.Errorf("%s must be a JSON object", name)
	}
	return object, nil
}

func requiredJSONString(object map[string]json.RawMessage, name string) (string, error) {
	value, exists, err := optionalJSONString(object, name)
	if err != nil || !exists || strings.TrimSpace(value) == "" {
		if err != nil {
			return "", err
		}
		return "", fmt.Errorf("%s is required", name)
	}
	return value, nil
}

func optionalJSONString(object map[string]json.RawMessage, name string) (string, bool, error) {
	raw, exists := object[name]
	if !exists {
		return "", false, nil
	}
	if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return "", true, fmt.Errorf("%s must be a string", name)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", true, fmt.Errorf("%s must be a string", name)
	}
	return value, true, nil
}

func isSupportedOutboundProtocol(protocol string) bool {
	switch protocol {
	case "vmess", "vless", "trojan", "shadowsocks", "socks", "http", "wireguard", "hysteria", "freedom", "blackhole", "dns", "loopback":
		return true
	default:
		return false
	}
}

func validateHysteria2Outbound(outbound map[string]json.RawMessage) error {
	settingsRaw, exists := outbound["settings"]
	if !exists {
		return fmt.Errorf("hysteria settings are required")
	}
	settings, err := decodeJSONObject(settingsRaw, "hysteria settings")
	if err != nil {
		return err
	}
	if err := requireJSONInteger(settings, "version", 2); err != nil {
		return fmt.Errorf("hysteria settings %w", err)
	}

	streamRaw, exists := outbound["streamSettings"]
	if !exists {
		return fmt.Errorf("hysteria streamSettings are required")
	}
	stream, err := decodeJSONObject(streamRaw, "hysteria streamSettings")
	if err != nil {
		return err
	}
	if err := requireJSONStringValue(stream, "network", "hysteria"); err != nil {
		return fmt.Errorf("hysteria streamSettings %w", err)
	}
	if err := requireJSONStringValue(stream, "security", "tls"); err != nil {
		return fmt.Errorf("hysteria streamSettings %w", err)
	}
	hysteriaRaw, exists := stream["hysteriaSettings"]
	if !exists {
		return fmt.Errorf("hysteriaSettings are required")
	}
	hysteriaSettings, err := decodeJSONObject(hysteriaRaw, "hysteriaSettings")
	if err != nil {
		return err
	}
	if err := requireJSONInteger(hysteriaSettings, "version", 2); err != nil {
		return fmt.Errorf("hysteriaSettings %w", err)
	}
	tlsRaw, exists := stream["tlsSettings"]
	if !exists {
		return fmt.Errorf("hysteria tlsSettings are required")
	}
	tlsSettings, err := decodeJSONObject(tlsRaw, "hysteria tlsSettings")
	if err != nil {
		return err
	}
	alpnRaw, exists := tlsSettings["alpn"]
	if !exists {
		return fmt.Errorf("hysteria TLS ALPN must include h3")
	}
	var alpn []string
	if err := json.Unmarshal(alpnRaw, &alpn); err != nil {
		return fmt.Errorf("hysteria TLS ALPN must be a string array")
	}
	for _, value := range alpn {
		if value == "h3" {
			return nil
		}
	}
	return fmt.Errorf("hysteria TLS ALPN must include h3")
}

func requireJSONInteger(object map[string]json.RawMessage, name string, expected int) error {
	raw, exists := object[name]
	if !exists {
		return fmt.Errorf("%s must be %d", name, expected)
	}
	var value int
	if err := json.Unmarshal(raw, &value); err != nil || value != expected {
		return fmt.Errorf("%s must be %d", name, expected)
	}
	return nil
}

func requireJSONStringValue(object map[string]json.RawMessage, name, expected string) error {
	value, err := requiredJSONString(object, name)
	if err != nil || value != expected {
		return fmt.Errorf("%s must be %s", name, expected)
	}
	return nil
}

func (c *Config) Equals(other *Config) bool {
	if len(c.InboundConfigs) != len(other.InboundConfigs) {
		return false
	}
	for i, inbound := range c.InboundConfigs {
		if !inbound.Equals(&other.InboundConfigs[i]) {
			return false
		}
	}
	if !bytes.Equal(c.LogConfig, other.LogConfig) {
		return false
	}
	if !bytes.Equal(c.RouterConfig, other.RouterConfig) {
		return false
	}
	if !bytes.Equal(c.DNSConfig, other.DNSConfig) {
		return false
	}
	if !bytes.Equal(c.OutboundConfigs, other.OutboundConfigs) {
		return false
	}
	if !bytes.Equal(c.Transport, other.Transport) {
		return false
	}
	if !bytes.Equal(c.Policy, other.Policy) {
		return false
	}
	if !bytes.Equal(c.API, other.API) {
		return false
	}
	if !bytes.Equal(c.Stats, other.Stats) {
		return false
	}
	if !bytes.Equal(c.Reverse, other.Reverse) {
		return false
	}
	if !bytes.Equal(c.FakeDNS, other.FakeDNS) {
		return false
	}
	return true
}
