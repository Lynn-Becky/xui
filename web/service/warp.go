package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"x-ui/logger"
	"x-ui/util/common"
	winguard "x-ui/util/wireguard"
)

const (
	warpAPIBase        = "https://api.cloudflareclient.com/v0a4005"
	warpClientVersion  = "a-6.30-3596"
	warpResponseLimit  = int64(10 << 20)
	warpRequestTimeout = 15 * time.Second
)

type WarpService struct {
	settingService SettingService
	apiBase        string
	httpClient     *http.Client
}

func NewWarpService() *WarpService {
	return &WarpService{
		apiBase:    warpAPIBase,
		httpClient: &http.Client{Timeout: warpRequestTimeout},
	}
}

func (s *WarpService) GetWarpData() (string, error) {
	return s.settingService.GetWarp()
}

func (s *WarpService) DelWarpData() error {
	return s.settingService.SetWarp("")
}

func (s *WarpService) GetWarpConfig() (string, error) {
	credentials, err := s.loadWarpCredentials()
	if err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		fmt.Sprintf("%s/reg/%s", s.baseURL(), credentials["device_id"]), nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Authorization", "Bearer "+credentials["access_token"])
	body, err := s.doRequest(request)
	return string(body), err
}

func (s *WarpService) RegWarp(privateKey, publicKey string) (string, error) {
	if err := winguard.ValidateKeypair(privateKey, publicKey); err != nil {
		return "", err
	}
	hostname, _ := os.Hostname()
	payload, err := json.Marshal(map[string]interface{}{
		"key":  publicKey,
		"tos":  time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"type": "PC", "model": "x-ui", "name": hostname,
	})
	if err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		s.baseURL()+"/reg", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	request.Header.Set("CF-Client-Version", warpClientVersion)
	request.Header.Set("Content-Type", "application/json")
	body, err := s.doRequest(request)
	if err != nil {
		return "", err
	}

	var response struct {
		ID      string `json:"id"`
		Token   string `json:"token"`
		Account struct {
			License string `json:"license"`
		} `json:"account"`
		Config map[string]interface{} `json:"config"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return "", err
	}
	if response.ID == "" || response.Token == "" || response.Account.License == "" {
		return "", common.NewError("warp register response is missing required account fields")
	}
	credentials := map[string]string{
		"access_token": response.Token,
		"device_id":    response.ID,
		"license_key":  response.Account.License,
		"private_key":  privateKey,
	}
	if clientID, ok := response.Config["client_id"].(string); ok && clientID != "" {
		credentials["client_id"] = clientID
	}
	stored, err := json.MarshalIndent(credentials, "", "  ")
	if err != nil {
		return "", err
	}
	if err := s.settingService.SetWarp(string(stored)); err != nil {
		return "", err
	}
	result, err := json.MarshalIndent(map[string]interface{}{
		"data":   credentials,
		"config": json.RawMessage(body),
	}, "", "  ")
	if err != nil {
		return "", err
	}
	return string(result), nil
}

func (s *WarpService) SetWarpLicense(license string) (string, error) {
	license = strings.TrimSpace(license)
	if len(license) < 26 {
		return "", common.NewError("warp license must contain at least 26 characters")
	}
	credentials, err := s.loadWarpCredentials()
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(map[string]string{"license": license})
	if err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPut,
		fmt.Sprintf("%s/reg/%s/account", s.baseURL(), credentials["device_id"]), bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	request.Header.Set("Authorization", "Bearer "+credentials["access_token"])
	request.Header.Set("Content-Type", "application/json")
	body, err := s.doRequest(request)
	if err != nil {
		return "", err
	}
	var response struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &response); err != nil || response.ID == "" {
		return "", common.NewError("warp set license returned an unexpected response")
	}
	credentials["license_key"] = license
	stored, err := json.MarshalIndent(credentials, "", "  ")
	if err != nil {
		return "", err
	}
	if err := s.settingService.SetWarp(string(stored)); err != nil {
		return "", err
	}
	return string(stored), nil
}

func (s *WarpService) ChangeWarpIP() (string, error) {
	oldCredentials, err := s.loadWarpCredentials()
	if err != nil {
		return "", err
	}
	if err := s.requireWarpOutbound(); err != nil {
		return "", err
	}
	privateKey, publicKey, err := winguard.GenerateKeypair()
	if err != nil {
		return "", err
	}
	result, err := s.RegWarp(privateKey, publicKey)
	if err != nil {
		return "", err
	}
	var parsed struct {
		Data   map[string]string      `json:"data"`
		Config map[string]interface{} `json:"config"`
	}
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		return "", err
	}
	if err := s.UpdateWarpXraySetting(parsed.Data, parsed.Config); err != nil {
		return "", err
	}
	if license := oldCredentials["license_key"]; len(license) >= 26 {
		if _, err := s.SetWarpLicense(license); err != nil {
			logger.Warning("WARP IP changed, but reapplying the existing license failed: ", err)
		}
	}
	return result, nil
}

func (s *WarpService) requireWarpOutbound() error {
	template, err := s.settingService.GetXrayConfigTemplate()
	if err != nil {
		return err
	}
	var root struct {
		Outbounds []struct {
			Tag      string `json:"tag"`
			Protocol string `json:"protocol"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal([]byte(template), &root); err != nil {
		return err
	}
	for _, outbound := range root.Outbounds {
		if outbound.Tag == "warp" {
			if outbound.Protocol != "wireguard" {
				return common.NewError("the warp outbound must use wireguard protocol")
			}
			return nil
		}
	}
	return common.NewError("warp outbound is not present in the xray template")
}

// UpdateWarpXraySetting updates only the existing tag=warp WireGuard outbound.
// Initial creation remains an explicit UI action so registration cannot alter
// routing by itself.
func (s *WarpService) UpdateWarpXraySetting(data map[string]string, config map[string]interface{}) error {
	template, err := s.settingService.GetXrayConfigTemplate()
	if err != nil {
		return err
	}
	var root map[string]interface{}
	if err := json.Unmarshal([]byte(template), &root); err != nil {
		return err
	}
	outbounds, ok := root["outbounds"].([]interface{})
	if !ok {
		return common.NewError("xray template outbounds must be an array")
	}
	updated := false
	for _, raw := range outbounds {
		outbound, ok := raw.(map[string]interface{})
		if !ok || outbound["tag"] != "warp" {
			continue
		}
		if protocol, _ := outbound["protocol"].(string); protocol != "wireguard" {
			return common.NewError("the warp outbound must use wireguard protocol")
		}
		settings, ok := outbound["settings"].(map[string]interface{})
		if !ok {
			return common.NewError("the warp outbound settings must be an object")
		}
		settings["secretKey"] = data["private_key"]
		applyWarpConfig(settings, data, config)
		updated = true
		break
	}
	if !updated {
		return common.NewError("warp outbound is not present in the xray template")
	}
	encoded, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	return s.settingService.SetXrayConfigTemplate(string(encoded))
}

func applyWarpConfig(settings map[string]interface{}, data map[string]string, response map[string]interface{}) {
	config, _ := response["config"].(map[string]interface{})
	if config == nil {
		return
	}
	if iface, ok := config["interface"].(map[string]interface{}); ok {
		if addresses, ok := iface["addresses"].(map[string]interface{}); ok {
			items := make([]string, 0, 2)
			if value, _ := addresses["v4"].(string); value != "" {
				items = append(items, value+"/32")
			}
			if value, _ := addresses["v6"].(string); value != "" {
				items = append(items, value+"/128")
			}
			if len(items) > 0 {
				settings["address"] = items
			}
		}
	}
	clientID, _ := config["client_id"].(string)
	if clientID == "" {
		clientID = data["client_id"]
	}
	if decoded, err := base64.StdEncoding.DecodeString(clientID); err == nil && len(decoded) > 0 {
		reserved := make([]int, len(decoded))
		for index, value := range decoded {
			reserved[index] = int(value)
		}
		settings["reserved"] = reserved
	}
	peers, _ := config["peers"].([]interface{})
	if len(peers) == 0 {
		return
	}
	cloudflarePeer, _ := peers[0].(map[string]interface{})
	if cloudflarePeer == nil {
		return
	}
	configuredPeers, _ := settings["peers"].([]interface{})
	var peer map[string]interface{}
	if len(configuredPeers) > 0 {
		peer, _ = configuredPeers[0].(map[string]interface{})
	}
	if peer == nil {
		peer = map[string]interface{}{"allowedIPs": []string{"0.0.0.0/0", "::/0"}}
		configuredPeers = []interface{}{peer}
		settings["peers"] = configuredPeers
	}
	if publicKey, _ := cloudflarePeer["public_key"].(string); publicKey != "" {
		peer["publicKey"] = publicKey
	}
	if endpoint, ok := cloudflarePeer["endpoint"].(map[string]interface{}); ok {
		if host, _ := endpoint["host"].(string); host != "" {
			peer["endpoint"] = host
		}
	}
}

func (s *WarpService) loadWarpCredentials() (map[string]string, error) {
	stored, err := s.settingService.GetWarp()
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(stored) == "" {
		return nil, common.NewError("warp is not registered")
	}
	credentials := make(map[string]string)
	if err := json.Unmarshal([]byte(stored), &credentials); err != nil {
		return nil, err
	}
	if credentials["access_token"] == "" || credentials["device_id"] == "" {
		return nil, common.NewError("warp credentials are incomplete")
	}
	return credentials, nil
}

func (s *WarpService) baseURL() string {
	if s.apiBase != "" {
		return strings.TrimRight(s.apiBase, "/")
	}
	return warpAPIBase
}

func (s *WarpService) client() *http.Client {
	if s.httpClient != nil {
		return s.httpClient
	}
	return &http.Client{Timeout: warpRequestTimeout}
}

func (s *WarpService) doRequest(request *http.Request) ([]byte, error) {
	response, err := s.client().Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, warpResponseLimit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > warpResponseLimit {
		return nil, common.NewError("warp api response is too large")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		if message := parseWarpError(body); message != "" {
			return nil, common.NewError(message)
		}
		return nil, common.NewErrorf("warp api returned status %d", response.StatusCode)
	}
	return body, nil
}

func parseWarpError(body []byte) string {
	var envelope struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if json.Unmarshal(body, &envelope) != nil || len(envelope.Errors) == 0 {
		return ""
	}
	return envelope.Errors[0].Message
}
