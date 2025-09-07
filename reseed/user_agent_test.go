package reseed

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Test for Bug #6: User Agent String Mismatch with I2P Compatibility
// This test verifies that the server strictly enforces the exact I2P user agent
// Only "Wget/1.11.4" is allowed - no other versions or variations
func TestUserAgentCompatibility(t *testing.T) {
	// Create a simple handler that just returns OK
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Wrap with our verification middleware
	handler := verifyMiddleware(testHandler)

	testCases := []struct {
		name           string
		userAgent      string
		expectedStatus int
		description    string
	}{
		{
			name:           "Exact match (current behavior)",
			userAgent:      "Wget/1.11.4",
			expectedStatus: http.StatusOK,
			description:    "Should accept the exact expected user agent",
		},
		{
			name:           "Newer wget version",
			userAgent:      "Wget/1.12.0",
			expectedStatus: http.StatusForbidden,
			description:    "Should reject newer wget versions - only exact I2P standard allowed",
		},
		{
			name:           "Much newer wget version",
			userAgent:      "Wget/1.20.3",
			expectedStatus: http.StatusForbidden,
			description:    "Should reject much newer wget versions - only exact I2P standard allowed",
		},
		{
			name:           "Invalid user agent (not wget)",
			userAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
			expectedStatus: http.StatusForbidden,
			description:    "Should reject non-wget user agents",
		},
		{
			name:           "Invalid user agent (curl)",
			userAgent:      "curl/7.68.0",
			expectedStatus: http.StatusForbidden,
			description:    "Should reject curl and other non-wget agents",
		},
		{
			name:           "Malformed wget version",
			userAgent:      "Wget/invalid",
			expectedStatus: http.StatusForbidden,
			description:    "Should reject malformed wget versions",
		},
		{
			name:           "Empty user agent",
			userAgent:      "",
			expectedStatus: http.StatusForbidden,
			description:    "Should reject empty user agent",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/i2pseeds.su3", nil)
			req.Header.Set("User-Agent", tc.userAgent)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d for user agent %q. %s",
					tc.expectedStatus, rr.Code, tc.userAgent, tc.description)
			}

			// Log the current behavior for visibility
			if tc.expectedStatus == http.StatusForbidden && rr.Code == http.StatusForbidden {
				t.Logf("BLOCKED (as expected): %s -> %d", tc.userAgent, rr.Code)
			} else if tc.expectedStatus == http.StatusOK && rr.Code == http.StatusOK {
				t.Logf("ALLOWED (as expected): %s -> %d", tc.userAgent, rr.Code)
			} else {
				t.Logf("MISMATCH: %s -> %d (expected %d)", tc.userAgent, rr.Code, tc.expectedStatus)
			}
		})
	}
}

// isValidI2PUserAgent validates if a user agent string is the exact I2P-required user agent
// According to I2P protocol specification, ONLY "Wget/1.11.4" is valid for SU3 bundle fetching
func isValidI2PUserAgent(userAgent string) bool {
	// I2P protocol requires exactly "Wget/1.11.4" - no other versions or variations allowed
	return userAgent == I2pUserAgent
}

// Test for the strict user agent validation (I2P protocol requirement)
func TestStrictUserAgentValidation(t *testing.T) {
	testCases := []struct {
		userAgent    string
		shouldAccept bool
		description  string
	}{
		{"Wget/1.11.4", true, "Only valid I2P user agent"},
		{"Wget/1.12.0", false, "Newer version not allowed"},
		{"Wget/1.20.3", false, "Much newer version not allowed"},
		{"Wget/2.0.0", false, "Major version upgrade not allowed"},
		{"wget/1.11.4", false, "Lowercase wget (case sensitive)"},
		{"Wget/1.11", false, "Missing patch version"},
		{"Wget/1.11.4.5", false, "Too many version parts"},
		{"Wget/1.11.4-ubuntu", false, "Version with suffix"},
		{"Wget/abc", false, "Non-numeric version"},
		{"Mozilla/5.0", false, "Browser user agent"},
		{"curl/7.68.0", false, "Curl user agent"},
		{"", false, "Empty user agent"},
		{"Wget", false, "No version"},
		{"Wget/", false, "Empty version"},
		{"Wget/1.11.3", false, "Older version not allowed"},
		{"Wget/1.10.4", false, "Older minor version not allowed"},
	}

	for _, tc := range testCases {
		t.Run(tc.userAgent, func(t *testing.T) {
			result := isValidI2PUserAgent(tc.userAgent)
			if result != tc.shouldAccept {
				t.Errorf("For user agent %q: expected %v, got %v. %s",
					tc.userAgent, tc.shouldAccept, result, tc.description)
			}
		})
	}
}
