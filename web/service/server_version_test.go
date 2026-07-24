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
	}

	for _, test := range tests {
		t.Run(test.version, func(t *testing.T) {
			if got := isSupportedXrayVersion(test.version); got != test.want {
				t.Fatalf("isSupportedXrayVersion(%q) = %t, want %t", test.version, got, test.want)
			}
		})
	}
}
