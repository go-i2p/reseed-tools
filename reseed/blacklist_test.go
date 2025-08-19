package reseed

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewBlacklist(t *testing.T) {
	bl := NewBlacklist()

	if bl == nil {
		t.Fatal("NewBlacklist() returned nil")
	}

	if bl.blacklist == nil {
		t.Error("blacklist map not initialized")
	}

	if len(bl.blacklist) != 0 {
		t.Error("blacklist should be empty initially")
	}
}

func TestBlacklist_BlockIP(t *testing.T) {
	tests := []struct {
		name string
		ip   string
	}{
		{"Valid IPv4", "192.168.1.1"},
		{"Valid IPv6", "2001:db8::1"},
		{"Localhost", "127.0.0.1"},
		{"Empty string", ""},
		{"Invalid IP format", "not.an.ip"},
		{"IP with port", "192.168.1.1:8080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bl := NewBlacklist()
			bl.BlockIP(tt.ip)

			// Check if IP was added to blacklist
			bl.m.RLock()
			blocked, exists := bl.blacklist[tt.ip]
			bl.m.RUnlock()

			if !exists {
				t.Errorf("IP %s was not added to blacklist", tt.ip)
			}

			if !blocked {
				t.Errorf("IP %s should be marked as blocked", tt.ip)
			}
		})
	}
}

func TestBlacklist_BlockIP_Concurrent(t *testing.T) {
	bl := NewBlacklist()
	var wg sync.WaitGroup

	// Test concurrent access to BlockIP
	ips := []string{"192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5"}

	for _, ip := range ips {
		wg.Add(1)
		go func(testIP string) {
			defer wg.Done()
			bl.BlockIP(testIP)
		}(ip)
	}

	wg.Wait()

	// Verify all IPs were blocked
	for _, ip := range ips {
		if !bl.isBlocked(ip) {
			t.Errorf("IP %s should be blocked after concurrent operations", ip)
		}
	}
}

func TestBlacklist_isBlocked(t *testing.T) {
	bl := NewBlacklist()

	// Test with non-blocked IP
	if bl.isBlocked("192.168.1.1") {
		t.Error("IP should not be blocked initially")
	}

	// Block an IP and test
	bl.BlockIP("192.168.1.1")
	if !bl.isBlocked("192.168.1.1") {
		t.Error("IP should be blocked after calling BlockIP")
	}

	// Test with different IP
	if bl.isBlocked("192.168.1.2") {
		t.Error("Different IP should not be blocked")
	}
}

func TestBlacklist_isBlocked_Concurrent(t *testing.T) {
	bl := NewBlacklist()
	bl.BlockIP("192.168.1.1")

	var wg sync.WaitGroup
	results := make([]bool, 10)

	// Test concurrent reads
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			results[index] = bl.isBlocked("192.168.1.1")
		}(i)
	}

	wg.Wait()

	// All reads should return true
	for i, result := range results {
		if !result {
			t.Errorf("Concurrent read %d should return true for blocked IP", i)
		}
	}
}

func TestBlacklist_LoadFile_Success(t *testing.T) {
	// Create temporary file with IP addresses
	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "blacklist.txt")

	ipList := "192.168.1.1\n192.168.1.2\n10.0.0.1\n127.0.0.1"
	err := os.WriteFile(tempFile, []byte(ipList), 0o644)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	bl := NewBlacklist()
	err = bl.LoadFile(tempFile)
	if err != nil {
		t.Fatalf("LoadFile() failed: %v", err)
	}

	// Test that all IPs from file are blocked
	expectedIPs := strings.Split(ipList, "\n")
	for _, ip := range expectedIPs {
		if !bl.isBlocked(ip) {
			t.Errorf("IP %s from file should be blocked", ip)
		}
	}
}

func TestBlacklist_LoadFile_EmptyFile(t *testing.T) {
	// Create empty temporary file
	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "empty_blacklist.txt")

	err := os.WriteFile(tempFile, []byte(""), 0o644)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	bl := NewBlacklist()
	err = bl.LoadFile(tempFile)
	if err != nil {
		t.Fatalf("LoadFile() should not fail with empty file: %v", err)
	}

	// Should have one entry (empty string)
	if !bl.isBlocked("") {
		t.Error("Empty string should be blocked when loading empty file")
	}
}

func TestBlacklist_LoadFile_FileNotFound(t *testing.T) {
	bl := NewBlacklist()
	err := bl.LoadFile("/nonexistent/file.txt")

	if err == nil {
		t.Error("LoadFile() should return error for non-existent file")
	}
}

func TestBlacklist_LoadFile_EmptyString(t *testing.T) {
	bl := NewBlacklist()
	err := bl.LoadFile("")
	if err != nil {
		t.Errorf("LoadFile() should not fail with empty filename: %v", err)
	}

	// Should not block anything when no file is provided
	if bl.isBlocked("192.168.1.1") {
		t.Error("No IPs should be blocked when empty filename provided")
	}
}

func TestBlacklist_LoadFile_WithWhitespace(t *testing.T) {
	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "whitespace_blacklist.txt")

	// File with various whitespace scenarios
	ipList := "192.168.1.1\n\n192.168.1.2\n   \n10.0.0.1\n"
	err := os.WriteFile(tempFile, []byte(ipList), 0o644)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	bl := NewBlacklist()
	err = bl.LoadFile(tempFile)
	if err != nil {
		t.Fatalf("LoadFile() failed: %v", err)
	}

	// Test specific IPs
	if !bl.isBlocked("192.168.1.1") {
		t.Error("IP 192.168.1.1 should be blocked")
	}
	if !bl.isBlocked("192.168.1.2") {
		t.Error("IP 192.168.1.2 should be blocked")
	}
	if !bl.isBlocked("10.0.0.1") {
		t.Error("IP 10.0.0.1 should be blocked")
	}

	// Empty lines should also be "blocked" as they are processed as strings
	if !bl.isBlocked("") {
		t.Error("Empty string should be blocked due to empty lines")
	}
}

func TestNewBlacklistListener(t *testing.T) {
	bl := NewBlacklist()

	// Create a test TCP listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create test listener: %v", err)
	}
	defer listener.Close()

	blListener := newBlacklistListener(listener, bl)

	if blListener.blacklist != bl {
		t.Error("blacklist reference not set correctly")
	}

	if blListener.TCPListener == nil {
		t.Error("TCPListener not set correctly")
	}
}

func TestBlacklistListener_Accept_AllowedConnection(t *testing.T) {
	bl := NewBlacklist()

	// Create a test TCP listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create test listener: %v", err)
	}
	defer listener.Close()

	blListener := newBlacklistListener(listener, bl)

	// Create a connection in a goroutine
	go func() {
		time.Sleep(10 * time.Millisecond) // Small delay to ensure Accept is called first
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err == nil {
			conn.Close()
		}
	}()

	conn, err := blListener.Accept()
	if err != nil {
		t.Fatalf("Accept() failed for allowed connection: %v", err)
	}

	if conn == nil {
		t.Error("Connection should not be nil for allowed IP")
	}

	if conn != nil {
		conn.Close()
	}
}

func TestBlacklistListener_Accept_BlockedConnection(t *testing.T) {
	bl := NewBlacklist()
	bl.BlockIP("127.0.0.1")

	// Create a test TCP listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create test listener: %v", err)
	}
	defer listener.Close()

	blListener := newBlacklistListener(listener, bl)

	// Create a connection in a goroutine
	go func() {
		time.Sleep(10 * time.Millisecond)
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err == nil {
			// Connection might be closed immediately, but that's expected
			conn.Close()
		}
	}()

	conn, err := blListener.Accept()
	// For blocked connections, Accept should return an error
	if err == nil {
		t.Error("Accept() should return an error for blocked connections")
		if conn != nil {
			conn.Close()
		}
	}

	if conn != nil {
		t.Error("Accept() should return nil connection for blocked IPs")
	}

	// Check that the error message is appropriate
	if err != nil && !strings.Contains(err.Error(), "blacklisted") {
		t.Errorf("Expected error message to contain 'blacklisted', got: %v", err)
	}
}

func TestBlacklistListener_Accept_ErrorBehavior(t *testing.T) {
	bl := NewBlacklist()
	bl.BlockIP("127.0.0.1")

	// Create a test TCP listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create test listener: %v", err)
	}
	defer listener.Close()

	blListener := newBlacklistListener(listener, bl)

	// Create a connection from the blacklisted IP
	go func() {
		time.Sleep(10 * time.Millisecond)
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err == nil {
			defer conn.Close()
			// Try to write some data to ensure connection is established
			conn.Write([]byte("test"))
		}
	}()

	conn, err := blListener.Accept()

	// Verify the error behavior
	if err == nil {
		t.Fatal("Expected error for blacklisted IP, got nil")
	}

	if conn != nil {
		t.Error("Expected nil connection for blacklisted IP, got non-nil")
	}

	expectedErrMsg := "connection rejected: IP address is blacklisted"
	if err.Error() != expectedErrMsg {
		t.Errorf("Expected error message '%s', got '%s'", expectedErrMsg, err.Error())
	}
}

func TestBlacklist_ThreadSafety(t *testing.T) {
	bl := NewBlacklist()
	var wg sync.WaitGroup

	// Test concurrent operations
	numGoroutines := 10
	numOperations := 100

	// Concurrent BlockIP operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				ip := "192.168." + string(rune(id)) + "." + string(rune(j))
				bl.BlockIP(ip)
			}
		}(i)
	}

	// Concurrent isBlocked operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				ip := "10.0." + string(rune(id)) + "." + string(rune(j))
				bl.isBlocked(ip) // Result doesn't matter, just testing for races
			}
		}(i)
	}

	wg.Wait()

	// If we get here without data races, the test passes
}
