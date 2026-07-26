package service

import "testing"

func TestIsSupportedXrayVersion(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{version: "v26.6.26", want: false},
		{version: "v26.6.27", want: true},
		{version: "v26.6.27-rc.1", want: false},
		{version: "v26.6.28", want: true},
		{version: "v26.10.0", want: true},
		{version: "v27.0.0", want: true},
		{version: "invalid", want: false},

		// installXray takes this straight from a URL path segment and
		// interpolates it into the download URL, so anything that is not a
		// plain release tag must be rejected.
		{version: "", want: false},
		{version: "../../attacker/xui/releases/download/1.0.0", want: false},
		{version: "26.6.27/../..", want: false},
		{version: "v26.6.27?x=", want: false},
		{version: "v26.6.27#frag", want: false},
		{version: "v26.6.-1", want: false},
		{version: "v9999.9999.9999", want: true},
	}

	for _, test := range tests {
		t.Run(test.version, func(t *testing.T) {
			if got := isSupportedXrayVersion(test.version); got != test.want {
				t.Fatalf("isSupportedXrayVersion(%q) = %t, want %t", test.version, got, test.want)
			}
		})
	}
}

// downloadXRay must refuse an unsupported tag before it builds a URL from it,
// so the endpoint cannot be used to install an arbitrary or downgraded release.
func TestDownloadXRayRejectsUnsupportedVersion(t *testing.T) {
	s := &ServerService{}
	for _, version := range []string{
		"",
		"v26.6.26",
		"../../attacker/xui/releases/download/1.0.0",
		"v26.6.27-rc.1",
	} {
		if _, err := s.downloadXRay(version); err == nil {
			t.Errorf("downloadXRay(%q) accepted an unsupported version", version)
		}
	}
}
