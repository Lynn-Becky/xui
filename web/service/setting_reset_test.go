package service

import "testing"

// ResetSettings must not clear anything that determines how the panel is
// reached. Clearing those silently returns an operator who configured TLS on a
// random port behind a random base path to plain HTTP on 54321 at "/", while the
// confirmation prompt only promises that the account survives.
func TestPreservedOnResetCoversPanelExposure(t *testing.T) {
	required := []string{
		"webPort",     // otherwise the panel moves back to 54321
		"webBasePath", // otherwise the random access path is lost
		"webCertFile", // otherwise TLS is silently torn down
		"webKeyFile",
		"secret", // otherwise every session is invalidated on a settings reset
	}

	preserved := make(map[string]bool, len(preservedOnReset))
	for _, key := range preservedOnReset {
		preserved[key] = true
	}

	for _, key := range required {
		if !preserved[key] {
			t.Errorf("%q is not preserved across a settings reset", key)
		}
	}
}

// Every preserved key must be a real setting, otherwise a rename would silently
// turn preservation back off.
func TestPreservedOnResetKeysExist(t *testing.T) {
	for _, key := range preservedOnReset {
		if _, ok := defaultValueMap[key]; !ok {
			t.Errorf("preserved key %q is not present in defaultValueMap", key)
		}
	}
}
