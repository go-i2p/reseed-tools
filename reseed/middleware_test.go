package reseed

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestProxiedMiddleware_ValidSingleIP tests that a single valid IP is extracted correctly
func TestProxiedMiddleware_ValidSingleIP(t *testing.T) {
	handler := proxiedMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RemoteAddr != "192.168.1.100" {
			t.Errorf("Expected RemoteAddr to be '192.168.1.100', got '%s'", r.RemoteAddr)
		}
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	req.RemoteAddr = "10.0.0.1:12345" // Original RemoteAddr

	handler.ServeHTTP(httptest.NewRecorder(), req)
}

// TestProxiedMiddleware_MultipleIPs tests that the first IP is extracted from comma-separated list
func TestProxiedMiddleware_MultipleIPs(t *testing.T) {
	testCases := []struct {
		name         string
		headerValue  string
		expectedAddr string
	}{
		{
			name:         "Two IPs",
			headerValue:  "1.2.3.4, 5.6.7.8",
			expectedAddr: "1.2.3.4",
		},
		{
			name:         "Three IPs",
			headerValue:  "1.2.3.4, 5.6.7.8, 9.10.11.12",
			expectedAddr: "1.2.3.4",
		},
		{
			name:         "Multiple IPs with varying whitespace",
			headerValue:  "203.0.113.45,  192.168.1.1,   10.0.0.1",
			expectedAddr: "203.0.113.45",
		},
		{
			name:         "IPs with tabs and spaces",
			headerValue:  "	172.16.0.1	, 192.168.1.1 , 10.0.0.1",
			expectedAddr: "172.16.0.1",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := proxiedMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.RemoteAddr != tc.expectedAddr {
					t.Errorf("Expected RemoteAddr to be '%s', got '%s'", tc.expectedAddr, r.RemoteAddr)
				}
			}))

			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("X-Forwarded-For", tc.headerValue)
			req.RemoteAddr = "10.0.0.1:12345"

			handler.ServeHTTP(httptest.NewRecorder(), req)
		})
	}
}

// TestProxiedMiddleware_IPv6 tests that IPv6 addresses are handled correctly
func TestProxiedMiddleware_IPv6(t *testing.T) {
	testCases := []struct {
		name         string
		headerValue  string
		expectedAddr string
	}{
		{
			name:         "Single IPv6",
			headerValue:  "2001:0db8:85a3::8a2e:0370:7334",
			expectedAddr: "2001:0db8:85a3::8a2e:0370:7334",
		},
		{
			name:         "IPv6 with IPv4",
			headerValue:  "2001:0db8:85a3::8a2e:0370:7334, 192.168.1.1",
			expectedAddr: "2001:0db8:85a3::8a2e:0370:7334",
		},
		{
			name:         "Compressed IPv6",
			headerValue:  "::1, 127.0.0.1",
			expectedAddr: "::1",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := proxiedMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.RemoteAddr != tc.expectedAddr {
					t.Errorf("Expected RemoteAddr to be '%s', got '%s'", tc.expectedAddr, r.RemoteAddr)
				}
			}))

			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("X-Forwarded-For", tc.headerValue)
			req.RemoteAddr = "10.0.0.1:12345"

			handler.ServeHTTP(httptest.NewRecorder(), req)
		})
	}
}

// TestProxiedMiddleware_InvalidIP tests that invalid IPs don't override RemoteAddr
func TestProxiedMiddleware_InvalidIP(t *testing.T) {
	testCases := []struct {
		name         string
		headerValue  string
		originalAddr string
	}{
		{
			name:         "Malformed IP",
			headerValue:  "999.999.999.999",
			originalAddr: "10.0.0.1:12345",
		},
		{
			name:         "Invalid format",
			headerValue:  "not-an-ip-address",
			originalAddr: "10.0.0.1:12345",
		},
		{
			name:         "Injection attempt",
			headerValue:  "1.2.3.4, <script>alert('xss')</script>",
			originalAddr: "10.0.0.1:12345",
		},
		{
			name:         "SQL injection attempt",
			headerValue:  "1' OR '1'='1",
			originalAddr: "10.0.0.1:12345",
		},
		{
			name:         "Empty string in list",
			headerValue:  ", 192.168.1.1",
			originalAddr: "10.0.0.1:12345",
		},
		{
			name:         "Only whitespace",
			headerValue:  "   ",
			originalAddr: "10.0.0.1:12345",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := proxiedMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// RemoteAddr should remain unchanged when invalid IP is provided
				if r.RemoteAddr != tc.originalAddr {
					t.Errorf("Expected RemoteAddr to remain '%s', got '%s'", tc.originalAddr, r.RemoteAddr)
				}
			}))

			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("X-Forwarded-For", tc.headerValue)
			req.RemoteAddr = tc.originalAddr

			handler.ServeHTTP(httptest.NewRecorder(), req)
		})
	}
}

// TestProxiedMiddleware_NoHeader tests that RemoteAddr is unchanged when no X-Forwarded-For header is present
func TestProxiedMiddleware_NoHeader(t *testing.T) {
	originalAddr := "10.0.0.1:12345"
	handler := proxiedMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RemoteAddr != originalAddr {
			t.Errorf("Expected RemoteAddr to remain '%s', got '%s'", originalAddr, r.RemoteAddr)
		}
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = originalAddr
	// No X-Forwarded-For header set

	handler.ServeHTTP(httptest.NewRecorder(), req)
}

// TestProxiedMiddleware_EmptyHeader tests that empty X-Forwarded-For header is handled safely
func TestProxiedMiddleware_EmptyHeader(t *testing.T) {
	originalAddr := "10.0.0.1:12345"
	handler := proxiedMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RemoteAddr != originalAddr {
			t.Errorf("Expected RemoteAddr to remain '%s', got '%s'", originalAddr, r.RemoteAddr)
		}
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "")
	req.RemoteAddr = originalAddr

	handler.ServeHTTP(httptest.NewRecorder(), req)
}

// TestProxiedMiddleware_RateLimitingBypass tests the original vulnerability
// This test verifies that the fix prevents rate limiting bypass via malformed headers
func TestProxiedMiddleware_RateLimitingBypass(t *testing.T) {
	// This is the attack scenario from the audit:
	// Attacker sends X-Forwarded-For: "1.2.3.4, 5.6.7.8" which previously
	// would be assigned directly to r.RemoteAddr, breaking rate limiting

	handler := proxiedMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// After the fix, r.RemoteAddr should contain only the first valid IP
		if r.RemoteAddr != "1.2.3.4" {
			t.Errorf("Expected RemoteAddr to be '1.2.3.4' (first IP), got '%s'", r.RemoteAddr)
		}
	}))

	req := httptest.NewRequest("GET", "/i2pseeds.su3", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")
	req.RemoteAddr = "10.0.0.1:12345"

	handler.ServeHTTP(httptest.NewRecorder(), req)
}

// TestProxiedMiddleware_BlacklistEvasion tests that blacklist checks work correctly
// This verifies that an attacker can't evade blacklisting by injecting comma-separated IPs
func TestProxiedMiddleware_BlacklistEvasion(t *testing.T) {
	// Scenario: IP 203.0.113.100 is blacklisted
	// Attacker tries to evade by sending: "203.0.113.100, 192.168.1.1"
	// The first IP should still be extracted for blacklist checking

	handler := proxiedMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RemoteAddr != "203.0.113.100" {
			t.Errorf("Expected RemoteAddr to be '203.0.113.100' (blacklisted IP), got '%s'", r.RemoteAddr)
		}
	}))

	req := httptest.NewRequest("GET", "/i2pseeds.su3", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.100, 192.168.1.1")
	req.RemoteAddr = "10.0.0.1:12345"

	handler.ServeHTTP(httptest.NewRecorder(), req)
}

// TestProxiedMiddleware_EdgeCases tests various edge cases
func TestProxiedMiddleware_EdgeCases(t *testing.T) {
	testCases := []struct {
		name         string
		headerValue  string
		originalAddr string
		expectedAddr string
	}{
		{
			name:         "Single comma",
			headerValue:  ",",
			originalAddr: "10.0.0.1:12345",
			expectedAddr: "10.0.0.1:12345", // Should remain unchanged
		},
		{
			name:         "Multiple commas",
			headerValue:  ",,,",
			originalAddr: "10.0.0.1:12345",
			expectedAddr: "10.0.0.1:12345", // Should remain unchanged
		},
		{
			name:         "Valid IP followed by garbage",
			headerValue:  "192.168.1.1, garbage, more-garbage",
			originalAddr: "10.0.0.1:12345",
			expectedAddr: "192.168.1.1", // Should extract first valid IP
		},
		{
			name:         "Spaces only between commas",
			headerValue:  " , , ",
			originalAddr: "10.0.0.1:12345",
			expectedAddr: "10.0.0.1:12345", // Should remain unchanged
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := proxiedMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.RemoteAddr != tc.expectedAddr {
					t.Errorf("Expected RemoteAddr to be '%s', got '%s'", tc.expectedAddr, r.RemoteAddr)
				}
			}))

			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("X-Forwarded-For", tc.headerValue)
			req.RemoteAddr = tc.originalAddr

			handler.ServeHTTP(httptest.NewRecorder(), req)
		})
	}
}
