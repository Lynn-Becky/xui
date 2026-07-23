package entity

import "testing"

func TestNormalizeBasePath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"panel", "/panel/"},
		{"/panel", "/panel/"},
		{"/panel/", "/panel/"},
		{"/", "/"},
	}

	for _, tt := range tests {
		got, err := NormalizeBasePath(tt.input)
		if err != nil {
			t.Fatalf("NormalizeBasePath(%q) returned an error: %v", tt.input, err)
		}
		if got != tt.want {
			t.Errorf("NormalizeBasePath(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNormalizeBasePathRejectsDangerousCharacters(t *testing.T) {
	for _, path := range []string{"panel path", `panel\\path`, "panel\npath", "panel\x7fpath"} {
		if _, err := NormalizeBasePath(path); err == nil {
			t.Errorf("NormalizeBasePath(%q) accepted a dangerous path", path)
		}
	}
}

func TestAllSettingCheckValidValidatesOutboundTemplate(t *testing.T) {
	base := AllSetting{
		WebPort:            54321,
		WebBasePath:        "/",
		TimeLocation:       "Asia/Shanghai",
		XrayTemplateConfig: `{"outbounds":[{"protocol":"freedom","settings":{}},{"protocol":"blackhole","tag":"blocked","settings":{}}]}`,
	}
	if err := base.CheckValid(); err != nil {
		t.Fatalf("valid outbound template rejected: %v", err)
	}
	base.XrayTemplateConfig = `{"outbounds":[{"protocol":"mtproto","settings":{}}]}`
	if err := base.CheckValid(); err == nil {
		t.Fatal("unsupported outbound protocol was accepted")
	}
}
