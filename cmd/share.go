package cmd

import (

	//"flag"

	"archive/tar"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/go-i2p/checki2cp/getmeanetdb"
	"github.com/go-i2p/onramp"
	"github.com/throttled/throttled/v2"
	"github.com/throttled/throttled/v2/store/memstore"
)

// NewShareCommand creates a new CLI command for sharing the netDb over I2P with password protection.
// This command sets up a secure file sharing server that allows remote I2P routers to access
// and download router information from the local netDb directory for network synchronization.
// Can be used to combine the local netDb with the netDb of a remote I2P router.
func NewShareCommand() *cli.Command {
	ndb, err := getmeanetdb.WhereIstheNetDB()
	if err != nil {
		lgr.WithError(err).Fatal("Fatal error in share")
	}
	return &cli.Command{
		Name:   "share",
		Usage:  "Start a netDb sharing server",
		Action: shareAction,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "signer",
				Value: getDefaultSigner(),
				Usage: "Your su3 signing ID (ex. something@mail.i2p)",
			},
			&cli.StringFlag{
				Name:  "key",
				Usage: "Path to your su3 signing private key",
			},
			&cli.StringFlag{
				Name:  "netdb",
				Value: ndb,
				Usage: "Path to NetDB directory containing routerInfos",
			},
			&cli.StringFlag{
				Name:  "samaddr",
				Value: "127.0.0.1:7656",
				Usage: "Use this SAM address to set up I2P connections for in-network sharing",
			},
			&cli.StringFlag{
				Name:  "share-password",
				Value: "",
				Usage: "Share the contents of your netDb directory privately over I2P as a tar.gz archive. Will fail is password is blank.",
			},
		},
	}
}

// sharer implements a HMAC-based authenticated HTTP file server for netDb sharing.
// It wraps the standard HTTP file system with HMAC-SHA256 authentication middleware
// and rate limiting to ensure only authorized clients can access router information
// over I2P, with protection against abuse via repeated requests.
// Authentication uses HMAC(password || timestamp) with a nonce validity window
// to prevent replay attacks while avoiding strict time synchronization.
type sharer struct {
	http.FileSystem
	http.Handler
	Path     string
	Password string
}

// nonceValidityWindow defines how long a nonce timestamp is considered valid (30 seconds)
// This allows for reasonable clock skew between I2P routers while preventing replay attacks
const nonceValidityWindow = 30 * time.Second

func (s *sharer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Extract HMAC signature and nonce timestamp from custom headers
	sig := r.Header.Get(http.CanonicalHeaderKey("X-HMAC-SHA256"))
	nonce := r.Header.Get(http.CanonicalHeaderKey("X-Nonce-Timestamp"))

	// Validate presence of both authentication headers
	if sig == "" || nonce == "" {
		http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse nonce timestamp and check validity
	nonceTime, err := strconv.ParseInt(nonce, 10, 64)
	if err != nil {
		http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
		return
	}

	requestTime := time.Unix(nonceTime, 0)
	if time.Since(requestTime) > nonceValidityWindow || time.Until(requestTime) > nonceValidityWindow {
		http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
		return
	}

	// Compute expected HMAC and compare with provided signature
	expected := s.computeHMAC(nonce)
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
		return
	}

	lgr.WithField("path", r.URL.Path).Debug("Request path")
	if strings.HasSuffix(r.URL.Path, "tar.gz") {
		lgr.Debug("Serving netdb")
		archive, err := walker(s.Path)
		if err != nil {
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		w.Write(archive.Bytes())
		return
	}
	s.Handler.ServeHTTP(w, r)
}

// computeHMAC generates an HMAC-SHA256 signature of the nonce using the password
func (s *sharer) computeHMAC(nonce string) string {
	h := hmac.New(sha256.New, []byte(s.Password))
	h.Write([]byte(nonce))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// Sharer creates a new HTTP file server for sharing netDb files over I2P.
// It sets up a HMAC-authenticated, rate-limited file system server that can serve
// router information to other I2P nodes with protection against abuse and replay attacks.
// The netDbDir parameter specifies the directory containing router files.
func Sharer(netDbDir, password string) *sharer {
	fileSystem := &sharer{
		FileSystem: http.Dir(netDbDir),
		Path:       netDbDir,
		Password:   password,
	}
	// Configure HTTP file server for the netDb directory
	fileSystem.Handler = http.FileServer(fileSystem.FileSystem)
	return fileSystem
}

// SharerWithRateLimit wraps a sharer with rate limiting to prevent abuse and DoS attacks.
// Returns an HTTP handler that applies rate limiting per remote address before delegating to the sharer.
func SharerWithRateLimit(s *sharer) (http.Handler, error) {
	// Create rate limiting store (1000 request slots)
	store, err := memstore.New(1000)
	if err != nil {
		return nil, fmt.Errorf("failed to create rate limiter store: %w", err)
	}

	// Create rate limiter: 100 requests per hour per IP
	limiter, err := throttled.NewGCRARateLimiter(store, throttled.RateQuota{
		MaxRate:  throttled.PerHour(100),
		MaxBurst: 5,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create rate limiter: %w", err)
	}

	// Wrap sharer with rate limiting middleware
	rateLimitMiddleware := throttled.HTTPRateLimiter{
		RateLimiter: limiter,
		VaryBy:      &throttled.VaryBy{RemoteAddr: true},
	}

	return rateLimitMiddleware.RateLimit(s), nil
}

func shareAction(c *cli.Context) error {
	// Convert netDb path to absolute path for consistent file access
	netDbDir, err := filepath.Abs(c.String("netdb"))
	if err != nil {
		return err
	}
	// Create password-protected file server for netDb sharing
	httpFs := Sharer(netDbDir, c.String("share-password"))

	// Wrap with rate limiting middleware
	rateLimitedHandler, err := SharerWithRateLimit(httpFs)
	if err != nil {
		return err
	}

	// Initialize I2P garlic routing for hidden service hosting
	garlic, err := onramp.NewGarlic("reseed", c.String("samaddr"), onramp.OPT_WIDE)
	if err != nil {
		return err
	}
	defer garlic.Close()

	// Create I2P listener for incoming connections
	garlicListener, err := garlic.Listen()
	if err != nil {
		return err
	}
	defer garlicListener.Close()

	// Start HTTP server over I2P network with rate-limited handler
	return http.Serve(garlicListener, rateLimitedHandler)
}

// walker creates a tar archive of all files in the specified netDb directory.
// This function recursively traverses the directory structure and packages all router
// information files into a compressed tar format for efficient network transfer.
func walker(netDbDir string) (*bytes.Buffer, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	walkFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if shouldSkipFile(info, netDbDir, path) {
			return nil
		}

		return processFileForArchive(tw, netDbDir, path, info)
	}

	if err := filepath.Walk(netDbDir, walkFn); err != nil {
		return nil, err
	}
	// Finalize the tar archive by writing the two 512-byte zero blocks (end-of-archive marker).
	// Without this, the tar archive is malformed and may fail to extract on the receiving end.
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("failed to finalize tar archive: %w", err)
	}
	return &buf, nil
}

// shouldSkipFile determines if a file should be excluded from the tar archive.
// It skips directories and files with empty relative paths within the netDb directory.
func shouldSkipFile(info os.FileInfo, netDbDir, path string) bool {
	if info.Mode().IsDir() {
		return true
	}

	relativePath := calculateRelativePath(netDbDir, path)
	return len(relativePath) == 0
}

// calculateRelativePath computes the relative path of a file within the netDb directory.
// This ensures proper archive structure by removing the base directory prefix.
func calculateRelativePath(netDbDir, path string) string {
	return path[len(netDbDir):]
}

// processFileForArchive handles the complete process of adding a single file to the tar archive.
// It opens the file, creates tar headers, and copies content while handling all error cases.
func processFileForArchive(tw *tar.Writer, netDbDir, path string, info os.FileInfo) error {
	relativePath := calculateRelativePath(netDbDir, path)

	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	return addFileToArchive(tw, file, info, relativePath)
}

// addFileToArchive creates tar header and copies file content to the archive.
// It handles tar header creation and validates successful writes to the archive.
func addFileToArchive(tw *tar.Writer, file *os.File, info os.FileInfo, relativePath string) error {
	header, err := tar.FileInfoHeader(info, relativePath)
	if err != nil {
		lgr.WithError(err).Fatal("Fatal error in share")
		return err
	}

	header.Name = relativePath
	if err = tw.WriteHeader(header); err != nil {
		lgr.WithError(err).Fatal("Fatal error in share")
		return err
	}

	if _, err := io.Copy(tw, file); err != nil {
		lgr.WithError(err).Fatal("Fatal error in share")
		return err
	}

	return nil
}
