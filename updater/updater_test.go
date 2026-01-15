package updater

import (
	"testing"
)

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name     string
		v1       string
		v2       string
		expected int
	}{
		{
			name:     "v1 greater than v2",
			v1:       "v1.2.0",
			v2:       "v1.1.0",
			expected: 1,
		},
		{
			name:     "v1 less than v2",
			v1:       "v1.0.0",
			v2:       "v1.1.0",
			expected: -1,
		},
		{
			name:     "v1 equals v2",
			v1:       "v1.0.0",
			v2:       "v1.0.0",
			expected: 0,
		},
		{
			name:     "without v prefix",
			v1:       "1.2.0",
			v2:       "1.1.0",
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compareVersions(tt.v1, tt.v2)
			if result != tt.expected {
				t.Errorf("compareVersions(%s, %s) = %d, want %d", tt.v1, tt.v2, result, tt.expected)
			}
		})
	}
}

func TestGetBinaryName(t *testing.T) {
	name := getBinaryName()
	if name == "" {
		t.Error("getBinaryName() returned empty string")
	}

	// Should contain "defenra-agent"
	if len(name) < len("defenra-agent") {
		t.Errorf("getBinaryName() = %s, expected longer name", name)
	}
}

func TestCheckForUpdate_DevVersion(t *testing.T) {
	hasUpdate, _, err := CheckForUpdate("dev")
	if err == nil {
		t.Error("CheckForUpdate(dev) should return error")
	}
	if hasUpdate {
		t.Error("CheckForUpdate(dev) should not have update")
	}
}
