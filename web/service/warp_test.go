package service

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestApplyWarpConfigPreservesPeerFields(t *testing.T) {
	settings := map[string]interface{}{
		"peers": []interface{}{map[string]interface{}{
			"allowedIPs": []interface{}{"10.0.0.0/8"},
			"keepAlive":  25,
		}},
	}
	data := map[string]string{"client_id": "AQID"}
	response := map[string]interface{}{"config": map[string]interface{}{
		"client_id": "AQID",
		"interface": map[string]interface{}{"addresses": map[string]interface{}{
			"v4": "172.16.0.2", "v6": "2606:4700::2",
		}},
		"peers": []interface{}{map[string]interface{}{
			"public_key": "public-key",
			"endpoint":   map[string]interface{}{"host": "engage.cloudflareclient.com:2408"},
		}},
	}}
	applyWarpConfig(settings, data, response)
	addresses := settings["address"].([]string)
	if len(addresses) != 2 || addresses[0] != "172.16.0.2/32" || addresses[1] != "2606:4700::2/128" {
		t.Fatalf("unexpected WARP addresses: %#v", addresses)
	}
	reserved := settings["reserved"].([]int)
	if len(reserved) != 3 || reserved[0] != 1 || reserved[2] != 3 {
		t.Fatalf("unexpected reserved bytes: %#v", reserved)
	}
	peer := settings["peers"].([]interface{})[0].(map[string]interface{})
	if peer["keepAlive"] != 25 || peer["publicKey"] != "public-key" || peer["endpoint"] != "engage.cloudflareclient.com:2408" {
		t.Fatalf("unexpected peer merge: %#v", peer)
	}
}

func TestWarpRequestRejectsAPIErrorAndOversizedBody(t *testing.T) {
	service := NewWarpService()
	service.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Body:       io.NopCloser(strings.NewReader(`{"errors":[{"message":"bad account"}]}`)),
			Header:     make(http.Header),
		}, nil
	})}
	request, _ := http.NewRequest(http.MethodGet, "https://api.cloudflareclient.com/test", nil)
	if _, err := service.doRequest(request); err == nil || !strings.Contains(err.Error(), "bad account") {
		t.Fatalf("unexpected API error: %v", err)
	}

	service.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(io.LimitReader(strings.NewReader(strings.Repeat("x", int(warpResponseLimit)+1)), warpResponseLimit+1)),
			Header:     make(http.Header),
		}, nil
	})}
	if _, err := service.doRequest(request); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("oversized response error = %v", err)
	}
}
