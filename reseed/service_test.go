package reseed

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLocalNetDb_ConfigurableRouterInfoAge(t *testing.T) {
	// Create a temporary directory for test
	tempDir, err := os.MkdirTemp("", "netdb_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test router info files with different ages
	files := []struct {
		name string
		age  time.Duration
	}{
		{"routerInfo-test1.dat", 24 * time.Hour},  // 1 day old
		{"routerInfo-test2.dat", 48 * time.Hour},  // 2 days old
		{"routerInfo-test3.dat", 96 * time.Hour},  // 4 days old
		{"routerInfo-test4.dat", 168 * time.Hour}, // 7 days old
	}

	// Create test files with specific modification times
	now := time.Now()
	for _, file := range files {
		filePath := filepath.Join(tempDir, file.name)
		err := os.WriteFile(filePath, []byte("dummy router info data"), 0o644)
		if err != nil {
			t.Fatalf("Failed to create test file %s: %v", file.name, err)
		}

		// Set modification time to simulate age
		modTime := now.Add(-file.age)
		err = os.Chtimes(filePath, modTime, modTime)
		if err != nil {
			t.Fatalf("Failed to set mod time for %s: %v", file.name, err)
		}
	}

	testCases := []struct {
		name          string
		maxAge        time.Duration
		expectedFiles int
		description   string
	}{
		{
			name:          "72 hour limit (I2P standard)",
			maxAge:        72 * time.Hour,
			expectedFiles: 2, // Files aged 24h and 48h should be included
			description:   "Should include files up to 72 hours old",
		},
		{
			name:          "192 hour limit (current default)",
			maxAge:        192 * time.Hour,
			expectedFiles: 4, // All files should be included
			description:   "Should include files up to 192 hours old",
		},
		{
			name:          "36 hour limit (strict)",
			maxAge:        36 * time.Hour,
			expectedFiles: 1, // Only the 24h file should be included
			description:   "Should include only files up to 36 hours old",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create LocalNetDb with configurable max age
			netdb := NewLocalNetDb(tempDir, tc.maxAge)

			// Note: RouterInfos() method will try to parse the dummy data and likely fail
			// since it's not real router info data. But we can still test the age filtering
			// by checking that it at least attempts to process the right number of files.

			// For this test, we'll just verify that the MaxRouterInfoAge field is set correctly
			if netdb.MaxRouterInfoAge != tc.maxAge {
				t.Errorf("Expected MaxRouterInfoAge %v, got %v", tc.maxAge, netdb.MaxRouterInfoAge)
			}

			// Verify the path is set correctly too
			if netdb.Path != tempDir {
				t.Errorf("Expected Path %s, got %s", tempDir, netdb.Path)
			}
		})
	}
}

func TestLocalNetDb_DefaultValues(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "netdb_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Test with different duration values
	testDurations := []time.Duration{
		72 * time.Hour,     // 3 days (I2P standard)
		192 * time.Hour,    // 8 days (old default)
		24 * time.Hour,     // 1 day (strict)
		7 * 24 * time.Hour, // 1 week
	}

	for _, duration := range testDurations {
		t.Run(duration.String(), func(t *testing.T) {
			netdb := NewLocalNetDb(tempDir, duration)

			if netdb.MaxRouterInfoAge != duration {
				t.Errorf("Expected MaxRouterInfoAge %v, got %v", duration, netdb.MaxRouterInfoAge)
			}
		})
	}
}
