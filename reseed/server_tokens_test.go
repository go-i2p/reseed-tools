package reseed

import (
	"testing"
	"time"
)

// Test for Bug #3: Unbounded Memory Growth in Acceptable Tokens (FIXED)
func TestAcceptableTokensMemoryBounds(t *testing.T) {
	server := &Server{}

	// Test 1: Verify tokens are cleaned up after expiration
	t.Run("ExpiredTokenCleanup", func(t *testing.T) {
		// Create some tokens and artificially age them
		server.acceptables = make(map[string]time.Time)
		oldTime := time.Now().Add(-5 * time.Minute) // Older than 4-minute expiry
		recentTime := time.Now()

		server.acceptables["old_token_1"] = oldTime
		server.acceptables["old_token_2"] = oldTime
		server.acceptables["recent_token"] = recentTime

		if len(server.acceptables) != 3 {
			t.Errorf("Expected 3 tokens initially, got %d", len(server.acceptables))
		}

		// Trigger cleanup by calling Acceptable
		_ = server.Acceptable()

		// Check that old tokens were cleaned up but recent one remains
		if len(server.acceptables) > 2 {
			t.Errorf("Expected at most 2 tokens after cleanup, got %d", len(server.acceptables))
		}

		// Verify recent token still exists
		if _, exists := server.acceptables["recent_token"]; !exists {
			t.Error("Recent token should not have been cleaned up")
		}

		// Verify old tokens were removed
		if _, exists := server.acceptables["old_token_1"]; exists {
			t.Error("Old token should have been cleaned up")
		}
	})

	// Test 2: Verify size-based eviction when too many tokens
	t.Run("SizeBasedEviction", func(t *testing.T) {
		server.acceptables = make(map[string]time.Time)

		// Add more than 50 tokens
		for i := 0; i < 60; i++ {
			token := server.Acceptable()
			// Ensure each token has a slightly different timestamp
			time.Sleep(1 * time.Millisecond)
			if token == "" {
				t.Error("Acceptable() should return a valid token")
			}
		}

		// Should be limited to around 50 tokens due to eviction
		if len(server.acceptables) > 55 {
			t.Errorf("Expected token count to be limited, got %d", len(server.acceptables))
		}
	})

	// Test 3: Verify token validation works correctly
	t.Run("TokenValidation", func(t *testing.T) {
		server.acceptables = make(map[string]time.Time)

		// Generate a token
		token := server.Acceptable()
		if token == "" {
			t.Fatal("Expected valid token")
		}

		// Verify token is valid
		if !server.CheckAcceptable(token) {
			t.Error("Token should be valid immediately after creation")
		}

		// Verify token is consumed (single-use)
		if server.CheckAcceptable(token) {
			t.Error("Token should not be valid after first use")
		}

		// Verify invalid token returns false
		if server.CheckAcceptable("invalid_token") {
			t.Error("Invalid token should return false")
		}
	})

	// Test 4: Verify memory doesn't grow unboundedly
	t.Run("UnboundedGrowthPrevention", func(t *testing.T) {
		server.acceptables = make(map[string]time.Time)

		// Generate many tokens without checking them
		// This was the original bug scenario
		for i := 0; i < 200; i++ {
			_ = server.Acceptable()
		}

		// Memory should be bounded
		if len(server.acceptables) > 60 {
			t.Errorf("Memory growth not properly bounded: %d tokens", len(server.acceptables))
		}

		t.Logf("Token map size after 200 generations: %d (should be bounded)", len(server.acceptables))
	})

	// Test 5: Test concurrent access safety
	t.Run("ConcurrentAccess", func(t *testing.T) {
		server.acceptables = make(map[string]time.Time)

		// Launch multiple goroutines generating and checking tokens
		done := make(chan bool, 4)

		// Token generators
		go func() {
			for i := 0; i < 50; i++ {
				_ = server.Acceptable()
			}
			done <- true
		}()

		go func() {
			for i := 0; i < 50; i++ {
				_ = server.Acceptable()
			}
			done <- true
		}()

		// Token checkers
		go func() {
			for i := 0; i < 25; i++ {
				token := server.Acceptable()
				_ = server.CheckAcceptable(token)
			}
			done <- true
		}()

		go func() {
			for i := 0; i < 25; i++ {
				token := server.Acceptable()
				_ = server.CheckAcceptable(token)
			}
			done <- true
		}()

		// Wait for all goroutines to complete
		for i := 0; i < 4; i++ {
			<-done
		}

		// Should not panic and should have bounded size
		if len(server.acceptables) > 100 {
			t.Errorf("Concurrent access resulted in unbounded growth: %d tokens", len(server.acceptables))
		}

		t.Logf("Token map size after concurrent access: %d", len(server.acceptables))
	})
}

// Test the cleanup methods directly
func TestTokenCleanupMethods(t *testing.T) {
	server := &Server{
		acceptables: make(map[string]time.Time),
	}

	// Test cleanupExpiredTokensUnsafe
	t.Run("CleanupExpired", func(t *testing.T) {
		now := time.Now()
		server.acceptables["expired1"] = now.Add(-5 * time.Minute)
		server.acceptables["expired2"] = now.Add(-6 * time.Minute)
		server.acceptables["valid"] = now

		server.cleanupExpiredTokensUnsafe()

		if len(server.acceptables) != 1 {
			t.Errorf("Expected 1 token after cleanup, got %d", len(server.acceptables))
		}

		if _, exists := server.acceptables["valid"]; !exists {
			t.Error("Valid token should remain after cleanup")
		}
	})

	// Test evictOldestTokensUnsafe
	t.Run("EvictOldest", func(t *testing.T) {
		server.acceptables = make(map[string]time.Time)
		now := time.Now()

		// Add tokens with different timestamps
		for i := 0; i < 10; i++ {
			server.acceptables[string(rune('a'+i))] = now.Add(time.Duration(-i) * time.Minute)
		}

		// Evict to keep only 5
		server.evictOldestTokensUnsafe(5)

		if len(server.acceptables) != 5 {
			t.Errorf("Expected 5 tokens after eviction, got %d", len(server.acceptables))
		}

		// The newest tokens should remain
		if _, exists := server.acceptables["a"]; !exists {
			t.Error("Newest token should remain after eviction")
		}
	})
}
