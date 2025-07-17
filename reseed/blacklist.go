package reseed

import (
	"errors"
	"net"
	"os"
	"strings"
	"sync"
)

// Blacklist manages a thread-safe collection of blocked IP addresses for reseed service security.
// It provides functionality to block specific IPs, load blacklists from files, and filter incoming
// connections to prevent access from malicious or unwanted sources. All operations are protected
// by a read-write mutex to support concurrent access patterns typical in network servers.
type Blacklist struct {
	// blacklist stores the blocked IP addresses as a map for O(1) lookup performance
	blacklist map[string]bool
	// m provides thread-safe access to the blacklist map using read-write semantics
	m sync.RWMutex
}

// NewBlacklist creates a new empty blacklist instance with initialized internal structures.
// Returns a ready-to-use Blacklist that can immediately accept IP blocking operations and
// concurrent access from multiple goroutines handling network connections.
func NewBlacklist() *Blacklist {
	return &Blacklist{blacklist: make(map[string]bool), m: sync.RWMutex{}}
}

// LoadFile reads IP addresses from a text file and adds them to the blacklist.
// Each line in the file should contain one IP address. Empty lines are ignored.
// Returns error if file cannot be read, otherwise successfully populates the blacklist.
func (s *Blacklist) LoadFile(file string) error {
	// Skip processing if empty filename provided to avoid unnecessary file operations
	if file != "" {
		if content, err := os.ReadFile(file); err == nil {
			// Process each line as a separate IP address for blocking
			for _, ip := range strings.Split(string(content), "\n") {
				s.BlockIP(ip)
			}
		} else {
			return err
		}
	}

	return nil
}

// BlockIP adds an IP address to the blacklist for connection filtering.
// The IP will be rejected in all future connection attempts until the blacklist is cleared.
// This method is thread-safe and can be called concurrently from multiple goroutines.
func (s *Blacklist) BlockIP(ip string) {
	// Acquire write lock to safely modify the blacklist map
	s.m.Lock()
	defer s.m.Unlock()

	s.blacklist[ip] = true
}

func (s *Blacklist) isBlocked(ip string) bool {
	// Use read lock for concurrent access during connection checking
	s.m.RLock()
	defer s.m.RUnlock()

	blocked, found := s.blacklist[ip]

	return found && blocked
}

type blacklistListener struct {
	*net.TCPListener
	blacklist *Blacklist
}

func (ln blacklistListener) Accept() (net.Conn, error) {
	// Accept incoming TCP connection for blacklist evaluation
	tc, err := ln.AcceptTCP()
	if err != nil {
		return nil, err
	}

	// Extract IP address from remote connection for blacklist checking
	ip, _, err := net.SplitHostPort(tc.RemoteAddr().String())
	if err != nil {
		tc.Close()
		return tc, err
	}

	// Reject connection immediately if IP is blacklisted for security
	if ln.blacklist.isBlocked(ip) {
		tc.Close()
		return nil, errors.New("connection rejected: IP address is blacklisted")
	}

	return tc, err
}

func newBlacklistListener(ln net.Listener, bl *Blacklist) blacklistListener {
	return blacklistListener{ln.(*net.TCPListener), bl}
}
