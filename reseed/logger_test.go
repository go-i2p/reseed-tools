package reseed

import (
	"os"
	"testing"

	"github.com/go-i2p/logger"
)

// TestLoggerIntegration verifies that the logger is properly integrated
func TestLoggerIntegration(t *testing.T) {
	// Test that logger instance is available
	if lgr == nil {
		t.Error("Logger instance lgr should not be nil")
	}

	// Test that logger responds to environment variables
	originalDebug := os.Getenv("DEBUG_I2P")
	originalWarnFail := os.Getenv("WARNFAIL_I2P")

	defer func() {
		os.Setenv("DEBUG_I2P", originalDebug)
		os.Setenv("WARNFAIL_I2P", originalWarnFail)
	}()

	// Test debug logging
	os.Setenv("DEBUG_I2P", "debug")
	os.Setenv("WARNFAIL_I2P", "")

	// Create a fresh logger instance to pick up env changes
	testLgr := logger.GetGoI2PLogger()

	// These should not panic and should be safe to call
	testLgr.Debug("Test debug message")
	testLgr.WithField("test", "value").Debug("Test structured debug message")
	testLgr.WithField("service", "test").WithField("status", "ok").Debug("Test multi-field message")

	// Test warning logging
	os.Setenv("DEBUG_I2P", "warn")
	testLgr = logger.GetGoI2PLogger()
	testLgr.Warn("Test warning message")

	// Test error logging
	os.Setenv("DEBUG_I2P", "error")
	testLgr = logger.GetGoI2PLogger()
	testLgr.WithField("error_type", "test").Error("Test error message")

	// Test that logging is disabled by default
	os.Setenv("DEBUG_I2P", "")
	testLgr = logger.GetGoI2PLogger()

	// These should be no-ops when logging is disabled
	testLgr.Debug("This should not appear")
	testLgr.Warn("This should not appear")
}

// TestStructuredLogging verifies the structured logging patterns used throughout the codebase
func TestStructuredLogging(t *testing.T) {
	// Set up debug logging for this test
	os.Setenv("DEBUG_I2P", "debug")
	defer os.Setenv("DEBUG_I2P", "")

	testLgr := logger.GetGoI2PLogger()

	// Test common patterns used in the codebase
	testLgr.WithField("service", "test").Debug("Service starting")
	testLgr.WithField("address", "127.0.0.1:8080").Debug("Server started")
	testLgr.WithField("protocol", "https").Debug("Protocol configured")

	// Test error patterns
	testErr := &testError{message: "test error"}
	testLgr.WithError(testErr).Error("Test error handling")
	testLgr.WithError(testErr).WithField("context", "test").Error("Test error with context")

	// Test performance logging patterns
	testLgr.WithField("total_allocs_kb", 1024).WithField("num_gc", 5).Debug("Memory stats")

	// Test I2P-specific patterns
	testLgr.WithField("sam_address", "127.0.0.1:7656").Debug("SAM connection configured")
	testLgr.WithField("netdb_path", "/tmp/test").Debug("NetDB path configured")
}

// testError implements error interface for testing
type testError struct {
	message string
}

func (e *testError) Error() string {
	return e.message
}

// BenchmarkLoggingOverhead measures the performance impact of logging when disabled
func BenchmarkLoggingOverhead(b *testing.B) {
	// Ensure logging is disabled
	os.Setenv("DEBUG_I2P", "")
	defer os.Setenv("DEBUG_I2P", "")

	testLgr := logger.GetGoI2PLogger()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		testLgr.WithField("iteration", i).Debug("Benchmark test message")
	}
}

// BenchmarkLoggingEnabled measures the performance impact of logging when enabled
func BenchmarkLoggingEnabled(b *testing.B) {
	// Enable debug logging
	os.Setenv("DEBUG_I2P", "debug")
	defer os.Setenv("DEBUG_I2P", "")

	testLgr := logger.GetGoI2PLogger()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		testLgr.WithField("iteration", i).Debug("Benchmark test message")
	}
}
