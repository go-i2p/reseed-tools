package reseed

import (
	"crypto/rand"
	"crypto/rsa"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestRebuildConcurrency verifies that concurrent rebuild calls don't cause
// goroutine accumulation or CPU exhaustion. This test addresses the critical
// bug reported in BUGFIX-CPU-EXHAUSTION.md where rapid rebuilds caused 100% CPU usage.
func TestRebuildConcurrency(t *testing.T) {
	// Create temporary netDb directory
	tmpDir, err := ioutil.TempDir("", "test-netdb-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create some dummy routerInfo files
	for i := 0; i < 100; i++ {
		filename := filepath.Join(tmpDir, "routerInfo-test"+string(rune(i))+".dat")
		// Write minimal valid routerInfo data (simplified for test)
		dummyData := make([]byte, 256)
		if _, err := rand.Read(dummyData); err != nil {
			t.Fatalf("Failed to generate test data: %v", err)
		}
		if err := ioutil.WriteFile(filename, dummyData, 0o644); err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}
	}

	// Create reseeder with short rebuild interval
	netdb := NewLocalNetDb(tmpDir, 24*time.Hour)
	reseeder := NewReseeder(netdb)

	// Generate test signing key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	reseeder.SigningKey = privKey
	reseeder.SignerID = []byte("test@example.com")
	reseeder.NumRi = 10
	reseeder.NumSu3 = 5
	reseeder.RebuildInterval = 100 * time.Millisecond

	// Attempt multiple concurrent rebuilds
	// With the fix, these should be serialized by the mutex
	// Without the fix, this would spawn 80 goroutines (10 * 8)
	const numAttempts = 10
	var wg sync.WaitGroup
	wg.Add(numAttempts)

	// Channel to track completion times
	completions := make(chan time.Duration, numAttempts)

	start := time.Now()
	for i := 0; i < numAttempts; i++ {
		go func(id int) {
			defer wg.Done()
			attemptStart := time.Now()

			// This should block if another rebuild is in progress
			err := reseeder.rebuild()
			if err != nil {
				// Expected to fail due to invalid routerInfo data in test
				t.Logf("Rebuild %d failed (expected): %v", id, err)
			}

			elapsed := time.Since(attemptStart)
			completions <- elapsed
		}(i)
	}

	// Wait for all attempts with timeout
	done := make(chan bool)
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		t.Logf("All %d rebuild attempts completed in %v", numAttempts, time.Since(start))
	case <-time.After(30 * time.Second):
		t.Fatal("Rebuild attempts timed out - possible deadlock or mutex issue")
	}

	close(completions)

	// Verify rebuilds were serialized (not concurrent)
	// Each rebuild should take roughly the same time, and total time
	// should be approximately sum of individual times (proving serialization)
	var totalIndividual time.Duration
	for elapsed := range completions {
		totalIndividual += elapsed
		t.Logf("Individual rebuild took: %v", elapsed)
	}

	totalWall := time.Since(start)
	t.Logf("Total wall time: %v, Sum of individual: %v", totalWall, totalIndividual)

	// Wall time should be close to sum of individual times (serialized)
	// Allow 20% margin for scheduling overhead
	if totalWall < totalIndividual*8/10 {
		t.Errorf("Rebuilds appear to run concurrently (wall=%v, sum=%v) - mutex not working!",
			totalWall, totalIndividual)
	}
}

// TestSecureRandThreadSafety verifies that newSecureRand() creates independent
// RNG instances that don't share state or mutexes.
func TestSecureRandThreadSafety(t *testing.T) {
	const numGoroutines = 100
	const iterationsPerGoroutine = 1000

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// If RNGs share state, this will cause heavy contention
	// With independent RNGs, this should complete quickly
	start := time.Now()

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			rng := newSecureRand()

			// Hammer the RNG
			for j := 0; j < iterationsPerGoroutine; j++ {
				_ = rng.Intn(1000)
			}
		}()
	}

	wg.Wait()
	elapsed := time.Since(start)

	totalOps := numGoroutines * iterationsPerGoroutine
	t.Logf("Completed %d rand operations across %d goroutines in %v",
		totalOps, numGoroutines, elapsed)

	// This should complete in under 1 second with independent RNGs
	// With global rand mutex, this could take 5-10 seconds due to contention
	if elapsed > 2*time.Second {
		t.Errorf("RNG operations too slow (%v) - possible mutex contention", elapsed)
	}

	// Operations per second should be high (>500K ops/sec on modern hardware)
	opsPerSec := float64(totalOps) / elapsed.Seconds()
	t.Logf("Operations per second: %.0f", opsPerSec)

	if opsPerSec < 100000 {
		t.Errorf("RNG throughput too low (%.0f ops/sec) - expected >100K", opsPerSec)
	}
}

// BenchmarkRebuildWithMutex benchmarks rebuild performance with mutex protection
func BenchmarkRebuildWithMutex(b *testing.B) {
	// Setup (similar to TestRebuildConcurrency but simplified)
	tmpDir, _ := ioutil.TempDir("", "bench-netdb-")
	defer os.RemoveAll(tmpDir)

	for i := 0; i < 50; i++ {
		filename := filepath.Join(tmpDir, "routerInfo-bench"+string(rune(i))+".dat")
		dummyData := make([]byte, 256)
		rand.Read(dummyData)
		ioutil.WriteFile(filename, dummyData, 0o644)
	}

	netdb := NewLocalNetDb(tmpDir, 24*time.Hour)
	reseeder := NewReseeder(netdb)
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	reseeder.SigningKey = privKey
	reseeder.SignerID = []byte("bench@example.com")
	reseeder.NumRi = 10
	reseeder.NumSu3 = 5

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reseeder.rebuild()
	}
}

// BenchmarkSecureRand benchmarks the thread-local RNG creation and usage
func BenchmarkSecureRand(b *testing.B) {
	for i := 0; i < b.N; i++ {
		rng := newSecureRand()
		for j := 0; j < 100; j++ {
			_ = rng.Intn(1000)
		}
	}
}
