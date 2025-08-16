package cmd

import (
	"context"
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"

	//"flag"
	"io/ioutil"
	"net"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/cretz/bine/tor"
	"github.com/cretz/bine/torutil"
	"github.com/cretz/bine/torutil/ed25519"
	"github.com/go-i2p/i2pkeys"
	"github.com/go-i2p/logger"
	"github.com/go-i2p/onramp"
	"github.com/go-i2p/sam3"
	"github.com/otiai10/copy"
	"github.com/rglonek/untar"
	"github.com/urfave/cli/v3"
	"i2pgit.org/go-i2p/reseed-tools/reseed"

	"github.com/go-i2p/checki2cp/getmeanetdb"
)

var lgr = logger.GetGoI2PLogger()

func getDefaultSigner() string {
	intentionalsigner := os.Getenv("RESEED_EMAIL")
	if intentionalsigner == "" {
		adminsigner := os.Getenv("MAILTO")
		if adminsigner != "" {
			return strings.Replace(adminsigner, "\n", "", -1)
		}
		return ""
	}
	return strings.Replace(intentionalsigner, "\n", "", -1)
}

func getHostName() string {
	hostname := os.Getenv("RESEED_HOSTNAME")
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	return strings.Replace(hostname, "\n", "", -1)
}

func providedReseeds(c *cli.Context) []string {
	reseedArg := c.StringSlice("friends")
	reseed.AllReseeds = reseedArg
	return reseed.AllReseeds
}

// NewReseedCommand creates a new CLI command for starting a reseed server.
// A reseed server provides bootstrap router information to help new I2P nodes join the network.
// The server supports multiple protocols (HTTP, HTTPS, I2P, Tor) and provides signed SU3 files
// containing router information for network bootstrapping.
func NewReseedCommand() *cli.Command {
	ndb, err := getmeanetdb.WhereIstheNetDB()
	if err != nil {
		lgr.WithError(err).Fatal("Failed to locate NetDB")
	}
	return &cli.Command{
		Name:   "reseed",
		Usage:  "Start a reseed server",
		Action: reseedAction,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "signer",
				Value: getDefaultSigner(),
				Usage: "Your su3 signing ID (ex. something@mail.i2p)",
			},
			&cli.StringFlag{
				Name:  "tlsHost",
				Value: getHostName(),
				Usage: "The public hostname used on your TLS certificate",
			},
			&cli.BoolFlag{
				Name:  "onion",
				Usage: "Present an onionv3 address",
			},
			&cli.BoolFlag{
				Name:  "singleOnion",
				Usage: "Use a faster, but non-anonymous single-hop onion",
			},
			&cli.StringFlag{
				Name:  "onionKey",
				Value: "onion.key",
				Usage: "Specify a path to an ed25519 private key for onion",
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
			&cli.DurationFlag{
				Name:  "routerInfoAge",
				Value: 72 * time.Hour,
				Usage: "Maximum age of router infos to include in reseed files (ex. 72h, 8d)",
			},
			&cli.StringFlag{
				Name:  "tlsCert",
				Usage: "Path to a TLS certificate",
			},
			&cli.StringFlag{
				Name:  "tlsKey",
				Usage: "Path to a TLS private key",
			},
			&cli.StringFlag{
				Name:  "ip",
				Value: "0.0.0.0",
				Usage: "IP address to listen on",
			},
			&cli.StringFlag{
				Name:  "port",
				Value: "8443",
				Usage: "Port to listen on",
			},
			&cli.IntFlag{
				Name:  "numRi",
				Value: 77,
				Usage: "Number of routerInfos to include in each su3 file",
			},
			&cli.IntFlag{
				Name:  "numSu3",
				Value: 50,
				Usage: "Number of su3 files to build (0 = automatic based on size of netdb)",
			},
			&cli.StringFlag{
				Name:  "interval",
				Value: "90h",
				Usage: "Duration between SU3 cache rebuilds (ex. 12h, 15m)",
			},
			&cli.StringFlag{
				Name:  "prefix",
				Value: "",
				Usage: "Prefix path for the HTTP(S) server. (ex. /netdb)",
			},
			&cli.BoolFlag{
				Name:  "trustProxy",
				Usage: "If provided, we will trust the 'X-Forwarded-For' header in requests (ex. behind cloudflare)",
			},
			&cli.StringFlag{
				Name:  "blacklist",
				Value: "",
				Usage: "Path to a txt file containing a list of IPs to deny connections from.",
			},
			&cli.DurationFlag{
				Name:  "stats",
				Value: 0,
				Usage: "Periodically print memory stats.",
			},
			&cli.BoolFlag{
				Name:  "i2p",
				Usage: "Listen for reseed request inside the I2P network",
			},
			&cli.BoolFlag{
				Name:  "yes",
				Usage: "Automatically answer 'yes' to self-signed SSL generation",
			},
			&cli.StringFlag{
				Name:  "samaddr",
				Value: "127.0.0.1:7656",
				Usage: "Use this SAM address to set up I2P connections for in-network reseed",
			},
			&cli.StringSliceFlag{
				Name:  "friends",
				Value: cli.NewStringSlice(reseed.AllReseeds...),
				Usage: "Ping other reseed servers and display the result on the homepage to provide information about reseed uptime.",
			},
			&cli.StringFlag{
				Name:  "share-peer",
				Value: "",
				Usage: "Download the shared netDb content of another I2P router, over I2P",
			},
			&cli.StringFlag{
				Name:  "share-password",
				Value: "",
				Usage: "Password for downloading netDb content from another router. Required for share-peer to work.",
			},
			&cli.BoolFlag{
				Name:  "acme",
				Usage: "Automatically generate a TLS certificate with the ACME protocol, defaults to Let's Encrypt",
			},
			&cli.StringFlag{
				Name:  "acmeserver",
				Value: "https://acme-staging-v02.api.letsencrypt.org/directory",
				Usage: "Use this server to issue a certificate with the ACME protocol",
			},
			&cli.IntFlag{
				Name:  "ratelimit",
				Value: 4,
				Usage: "Maximum number of reseed bundle requests per-IP address, per-hour.",
			},
			&cli.IntFlag{
				Name:  "ratelimitweb",
				Value: 40,
				Usage: "Maxiumum number of web-visits per-IP address, per-hour",
			},
		},
	}
}

// CreateEepServiceKey generates new I2P keys for eepSite (hidden service) operation.
// It connects to the I2P SAM interface and creates a fresh key pair for hosting services
// on the I2P network. Returns the generated keys or an error if SAM connection fails.
func CreateEepServiceKey(c *cli.Context) (i2pkeys.I2PKeys, error) {
	// Connect to I2P SAM interface for key generation
	sam, err := sam3.NewSAM(c.String("samaddr"))
	if err != nil {
		return i2pkeys.I2PKeys{}, err
	}
	defer sam.Close()
	// Generate new I2P destination keys
	k, err := sam.NewKeys()
	if err != nil {
		return i2pkeys.I2PKeys{}, err
	}
	return k, err
}

// LoadKeys loads existing I2P keys from file or creates new ones if the file doesn't exist.
// This function handles the key management lifecycle for I2P services, automatically
// generating keys when needed and persisting them for reuse across restarts.
func LoadKeys(keysPath string, c *cli.Context) (i2pkeys.I2PKeys, error) {
	// Check if keys file exists, create new keys if not found
	if _, err := os.Stat(keysPath); os.IsNotExist(err) {
		keys, err := CreateEepServiceKey(c)
		if err != nil {
			return i2pkeys.I2PKeys{}, err
		}
		file, err := os.Create(keysPath)
		if err != nil {
			return i2pkeys.I2PKeys{}, err
		}
		defer file.Close()
		err = i2pkeys.StoreKeysIncompat(keys, file)
		if err != nil {
			return i2pkeys.I2PKeys{}, err
		}
		return keys, nil
	} else if err == nil {
		file, err := os.Open(keysPath)
		if err != nil {
			return i2pkeys.I2PKeys{}, err
		}
		defer file.Close()
		keys, err := i2pkeys.LoadKeysIncompat(file)
		if err != nil {
			return i2pkeys.I2PKeys{}, err
		}
		return keys, nil
	} else {
		return i2pkeys.I2PKeys{}, err
	}
}

// fileExists checks if a file exists and is not a directory before we
// try using it to prevent further errors.
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// reseedAction is the main entry point for the reseed command.
// It orchestrates the configuration and startup of the reseed server.
func reseedAction(c *cli.Context) error {
	// Validate required configuration parameters
	netdbDir, signerID, err := validateRequiredConfig(c)
	if err != nil {
		return err
	}

	// Setup remote NetDB sharing if configured
	if err := setupRemoteNetDBSharing(c); err != nil {
		return err
	}

	// Configure TLS certificates for all protocols
	tlsConfig, err := configureTLSCertificates(c)
	if err != nil {
		return err
	}

	// Setup I2P keys if I2P protocol is enabled
	i2pkey, err := setupI2PKeys(c, tlsConfig)
	if err != nil {
		return err
	}

	// Setup Onion keys if Onion protocol is enabled
	if err := setupOnionKeys(c, tlsConfig); err != nil {
		return err
	}

	// Parse configuration and setup signing keys
	reloadIntvl, privKey, err := setupSigningConfiguration(c, signerID)
	if err != nil {
		return err
	}

	// Initialize reseeder with configured parameters
	reseeder, err := initializeReseeder(c, netdbDir, signerID, privKey, reloadIntvl)
	if err != nil {
		return err
	}

	// Start all configured servers
	startConfiguredServers(c, tlsConfig, i2pkey, reseeder)
	return nil
}

// validateRequiredConfig validates and returns the required netdb and signer configuration.
func validateRequiredConfig(c *cli.Context) (string, string, error) {
	providedReseeds(c)

	netdbDir := c.String("netdb")
	if netdbDir == "" {
		fmt.Println("--netdb is required")
		return "", "", fmt.Errorf("--netdb is required")
	}

	signerID := c.String("signer")
	if signerID == "" || signerID == "you@mail.i2p" {
		fmt.Println("--signer is required")
		return "", "", fmt.Errorf("--signer is required")
	}

	if !strings.Contains(signerID, "@") {
		if !fileExists(signerID) {
			fmt.Println("--signer must be an email address or a file containing an email address.")
			return "", "", fmt.Errorf("--signer must be an email address or a file containing an email address.")
		}
		bytes, err := ioutil.ReadFile(signerID)
		if err != nil {
			fmt.Println("--signer must be an email address or a file containing an email address.")
			return "", "", fmt.Errorf("--signer must be an email address or a file containing an email address.")
		}
		signerID = string(bytes)
	}

	return netdbDir, signerID, nil
}

// setupRemoteNetDBSharing configures and starts remote NetDB downloading if share-peer is specified.
func setupRemoteNetDBSharing(c *cli.Context) error {
	if c.String("share-peer") != "" {
		count := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
		for i := range count {
			err := downloadRemoteNetDB(c.String("share-peer"), c.String("share-password"), c.String("netdb"), c.String("samaddr"))
			if err != nil {
				lgr.WithError(err).WithField("attempt", i).WithField("attempts_remaining", 10-i).Warn("Error downloading remote netDb, retrying in 10 seconds")
				time.Sleep(time.Second * 10)
			} else {
				break
			}
		}
		go getSupplementalNetDb(c.String("share-peer"), c.String("share-password"), c.String("netdb"), c.String("samaddr"))
	}
	return nil
}

// tlsConfiguration holds TLS certificate configuration for different protocols.
type tlsConfiguration struct {
	tlsCert, tlsKey           string
	tlsHost                   string
	onionTlsCert, onionTlsKey string
	onionTlsHost              string
	i2pTlsCert, i2pTlsKey     string
	i2pTlsHost                string
}

// configureTLSCertificates sets up TLS certificates and keys for HTTP/HTTPS protocol.
func configureTLSCertificates(c *cli.Context) (*tlsConfiguration, error) {
	config := &tlsConfiguration{
		tlsHost: c.String("tlsHost"),
	}

	if config.tlsHost != "" {
		config.onionTlsHost = config.tlsHost
		config.i2pTlsHost = config.tlsHost

		config.tlsKey = c.String("tlsKey")
		if config.tlsKey == "" {
			config.tlsKey = config.tlsHost + ".pem"
			config.onionTlsKey = config.tlsHost + ".pem"
			config.i2pTlsKey = config.tlsHost + ".pem"
		}

		config.tlsCert = c.String("tlsCert")
		if config.tlsCert == "" {
			config.tlsCert = config.tlsHost + ".crt"
			config.onionTlsCert = config.tlsHost + ".crt"
			config.i2pTlsCert = config.tlsHost + ".crt"
		}

		auto := c.Bool("yes")
		ignore := c.Bool("trustProxy")
		if !ignore {
			acme := c.Bool("acme")
			if acme {
				acmeserver := c.String("acmeserver")
				err := checkUseAcmeCert(config.tlsHost, "", acmeserver, &config.tlsCert, &config.tlsKey, auto)
				if err != nil {
					lgr.WithError(err).Fatal("Fatal error")
				}
			} else {
				err := checkOrNewTLSCert(config.tlsHost, &config.tlsCert, &config.tlsKey, auto)
				if err != nil {
					lgr.WithError(err).Fatal("Fatal error")
				}
			}
		}
	}

	return config, nil
}

// setupI2PKeys configures I2P keys and TLS certificates if I2P protocol is enabled.
func setupI2PKeys(c *cli.Context, tlsConfig *tlsConfiguration) (i2pkeys.I2PKeys, error) {
	var i2pkey i2pkeys.I2PKeys

	if c.Bool("i2p") {
		var err error
		i2pkey, err = LoadKeys("reseed.i2pkeys", c)
		if err != nil {
			lgr.WithError(err).Fatal("Fatal error")
		}

		if tlsConfig.i2pTlsHost == "" {
			tlsConfig.i2pTlsHost = i2pkey.Addr().Base32()
		}

		if tlsConfig.i2pTlsHost != "" {
			if tlsConfig.i2pTlsKey == "" {
				tlsConfig.i2pTlsKey = tlsConfig.i2pTlsHost + ".pem"
			}

			if tlsConfig.i2pTlsCert == "" {
				tlsConfig.i2pTlsCert = tlsConfig.i2pTlsHost + ".crt"
			}

			auto := c.Bool("yes")
			ignore := c.Bool("trustProxy")
			if !ignore {
				err := checkOrNewTLSCert(tlsConfig.i2pTlsHost, &tlsConfig.i2pTlsCert, &tlsConfig.i2pTlsKey, auto)
				if err != nil {
					lgr.WithError(err).Fatal("Fatal error")
				}
			}
		}
	}

	return i2pkey, nil
}

// setupOnionKeys configures Onion service keys and TLS certificates if Onion protocol is enabled.
func setupOnionKeys(c *cli.Context, tlsConfig *tlsConfiguration) error {
	if c.Bool("onion") {
		var ok []byte
		var err error

		if _, err = os.Stat(c.String("onionKey")); err == nil {
			ok, err = ioutil.ReadFile(c.String("onionKey"))
			if err != nil {
				lgr.WithError(err).Fatal("Fatal error")
			}
		} else {
			key, err := ed25519.GenerateKey(nil)
			if err != nil {
				lgr.WithError(err).Fatal("Fatal error")
			}
			ok = []byte(key.PrivateKey())
		}

		if tlsConfig.onionTlsHost == "" {
			tlsConfig.onionTlsHost = torutil.OnionServiceIDFromPrivateKey(ed25519.PrivateKey(ok)) + ".onion"
		}

		err = ioutil.WriteFile(c.String("onionKey"), ok, 0o644)
		if err != nil {
			lgr.WithError(err).Fatal("Fatal error")
		}

		if tlsConfig.onionTlsHost != "" {
			if tlsConfig.onionTlsKey == "" {
				tlsConfig.onionTlsKey = tlsConfig.onionTlsHost + ".pem"
			}

			if tlsConfig.onionTlsCert == "" {
				tlsConfig.onionTlsCert = tlsConfig.onionTlsHost + ".crt"
			}

			auto := c.Bool("yes")
			ignore := c.Bool("trustProxy")
			if !ignore {
				err := checkOrNewTLSCert(tlsConfig.onionTlsHost, &tlsConfig.onionTlsCert, &tlsConfig.onionTlsKey, auto)
				if err != nil {
					lgr.WithError(err).Fatal("Fatal error")
				}
			}
		}
	}

	return nil
}

// setupSigningConfiguration parses duration and sets up signing certificates.
func setupSigningConfiguration(c *cli.Context, signerID string) (time.Duration, *rsa.PrivateKey, error) {
	reloadIntvl, err := time.ParseDuration(c.String("interval"))
	if err != nil {
		fmt.Printf("'%s' is not a valid time interval.\n", reloadIntvl)
		return 0, nil, fmt.Errorf("'%s' is not a valid time interval.\n", reloadIntvl)
	}

	signerKey := c.String("key")
	if signerKey == "" {
		signerKey = signerFile(signerID) + ".pem"
	}

	auto := c.Bool("yes")
	privKey, err := getOrNewSigningCert(&signerKey, signerID, auto)
	if err != nil {
		lgr.WithError(err).Fatal("Fatal error")
	}

	return reloadIntvl, privKey, nil
}

// initializeReseeder creates and configures a new reseeder instance.
func initializeReseeder(c *cli.Context, netdbDir, signerID string, privKey *rsa.PrivateKey, reloadIntvl time.Duration) (*reseed.ReseederImpl, error) {
	routerInfoAge := c.Duration("routerInfoAge")
	netdb := reseed.NewLocalNetDb(netdbDir, routerInfoAge)

	reseeder := reseed.NewReseeder(netdb)
	reseeder.SigningKey = privKey
	reseeder.SignerID = []byte(signerID)
	reseeder.NumRi = c.Int("numRi")
	reseeder.NumSu3 = c.Int("numSu3")
	reseeder.RebuildInterval = reloadIntvl
	reseeder.Start()

	return reseeder, nil
}

// Context-aware server functions that return errors instead of calling Fatal
func reseedHTTPSWithContext(ctx context.Context, c *cli.Context, tlsCert, tlsKey string, reseeder *reseed.ReseederImpl) error {
	server := reseed.NewServer(c.String("prefix"), c.Bool("trustProxy"))
	server.Reseeder = reseeder
	server.RequestRateLimit = c.Int("ratelimit")
	server.WebRateLimit = c.Int("ratelimitweb")
	server.Addr = net.JoinHostPort(c.String("ip"), c.String("port"))

	// load a blacklist
	blacklist := reseed.NewBlacklist()
	server.Blacklist = blacklist
	blacklistFile := c.String("blacklist")
	if "" != blacklistFile {
		blacklist.LoadFile(blacklistFile)
	}

	// print stats once in a while
	if c.Duration("stats") != 0 {
		go func() {
			var mem runtime.MemStats
			ticker := time.NewTicker(c.Duration("stats"))
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					runtime.ReadMemStats(&mem)
					lgr.WithField("total_allocs_kb", mem.TotalAlloc/1024).WithField("allocs_kb", mem.Alloc/1024).WithField("mallocs", mem.Mallocs).WithField("num_gc", mem.NumGC).Debug("Memory stats")
				}
			}
		}()
	}

	lgr.WithField("address", server.Addr).Debug("HTTPS server started")
	return server.ListenAndServeTLS(tlsCert, tlsKey)
}

func reseedHTTPWithContext(ctx context.Context, c *cli.Context, reseeder *reseed.ReseederImpl) error {
	server := reseed.NewServer(c.String("prefix"), c.Bool("trustProxy"))
	server.RequestRateLimit = c.Int("ratelimit")
	server.WebRateLimit = c.Int("ratelimitweb")
	server.Reseeder = reseeder
	server.Addr = net.JoinHostPort(c.String("ip"), c.String("port"))

	// load a blacklist
	blacklist := reseed.NewBlacklist()
	server.Blacklist = blacklist
	blacklistFile := c.String("blacklist")
	if "" != blacklistFile {
		blacklist.LoadFile(blacklistFile)
	}

	// print stats once in a while
	if c.Duration("stats") != 0 {
		go func() {
			var mem runtime.MemStats
			ticker := time.NewTicker(c.Duration("stats"))
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					runtime.ReadMemStats(&mem)
					lgr.WithField("total_allocs_kb", mem.TotalAlloc/1024).WithField("allocs_kb", mem.Alloc/1024).WithField("mallocs", mem.Mallocs).WithField("num_gc", mem.NumGC).Debug("Memory stats")
				}
			}
		}()
	}

	lgr.WithField("address", server.Addr).Debug("HTTP server started")
	return server.ListenAndServe()
}

func reseedOnionWithContext(ctx context.Context, c *cli.Context, onionTlsCert, onionTlsKey string, reseeder *reseed.ReseederImpl) error {
	server := reseed.NewServer(c.String("prefix"), c.Bool("trustProxy"))
	server.Reseeder = reseeder
	server.Addr = net.JoinHostPort(c.String("ip"), c.String("port"))

	// load a blacklist
	blacklist := reseed.NewBlacklist()
	server.Blacklist = blacklist
	blacklistFile := c.String("blacklist")
	if "" != blacklistFile {
		blacklist.LoadFile(blacklistFile)
	}

	// print stats once in a while
	if c.Duration("stats") != 0 {
		go func() {
			var mem runtime.MemStats
			ticker := time.NewTicker(c.Duration("stats"))
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					runtime.ReadMemStats(&mem)
					lgr.WithField("total_allocs_kb", mem.TotalAlloc/1024).WithField("allocs_kb", mem.Alloc/1024).WithField("mallocs", mem.Mallocs).WithField("num_gc", mem.NumGC).Debug("Memory stats")
				}
			}
		}()
	}

	port, err := strconv.Atoi(c.String("port"))
	if err != nil {
		return fmt.Errorf("invalid port: %w", err)
	}
	port += 1

	if _, err := os.Stat(c.String("onionKey")); err == nil {
		ok, err := ioutil.ReadFile(c.String("onionKey"))
		if err != nil {
			return fmt.Errorf("failed to read onion key: %w", err)
		}

		if onionTlsCert != "" && onionTlsKey != "" {
			tlc := &tor.ListenConf{
				LocalPort:    port,
				Key:          ed25519.PrivateKey(ok),
				RemotePorts:  []int{443},
				Version3:     true,
				NonAnonymous: c.Bool("singleOnion"),
				DiscardKey:   false,
			}
			return server.ListenAndServeOnionTLS(nil, tlc, onionTlsCert, onionTlsKey)
		} else {
			tlc := &tor.ListenConf{
				LocalPort:    port,
				Key:          ed25519.PrivateKey(ok),
				RemotePorts:  []int{80},
				Version3:     true,
				NonAnonymous: c.Bool("singleOnion"),
				DiscardKey:   false,
			}
			return server.ListenAndServeOnion(nil, tlc)
		}
	} else if os.IsNotExist(err) {
		tlc := &tor.ListenConf{
			LocalPort:    port,
			RemotePorts:  []int{80},
			Version3:     true,
			NonAnonymous: c.Bool("singleOnion"),
			DiscardKey:   false,
		}
		return server.ListenAndServeOnion(nil, tlc)
	}

	return fmt.Errorf("onion key file error: %w", err)
}

func reseedI2PWithContext(ctx context.Context, c *cli.Context, i2pTlsCert, i2pTlsKey string, i2pIdentKey i2pkeys.I2PKeys, reseeder *reseed.ReseederImpl) error {
	server := reseed.NewServer(c.String("prefix"), c.Bool("trustProxy"))
	server.RequestRateLimit = c.Int("ratelimit")
	server.WebRateLimit = c.Int("ratelimitweb")
	server.Reseeder = reseeder
	server.Addr = net.JoinHostPort(c.String("ip"), c.String("port"))

	// load a blacklist
	blacklist := reseed.NewBlacklist()
	server.Blacklist = blacklist
	blacklistFile := c.String("blacklist")
	if "" != blacklistFile {
		blacklist.LoadFile(blacklistFile)
	}

	// print stats once in a while
	if c.Duration("stats") != 0 {
		go func() {
			var mem runtime.MemStats
			ticker := time.NewTicker(c.Duration("stats"))
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					runtime.ReadMemStats(&mem)
					lgr.WithField("total_allocs_kb", mem.TotalAlloc/1024).WithField("allocs_kb", mem.Alloc/1024).WithField("mallocs", mem.Mallocs).WithField("num_gc", mem.NumGC).Debug("Memory stats")
				}
			}
		}()
	}

	port, err := strconv.Atoi(c.String("port"))
	if err != nil {
		return fmt.Errorf("invalid port: %w", err)
	}
	port += 1

	if i2pTlsCert != "" && i2pTlsKey != "" {
		return server.ListenAndServeI2PTLS(c.String("samaddr"), i2pIdentKey, i2pTlsCert, i2pTlsKey)
	} else {
		return server.ListenAndServeI2P(c.String("samaddr"), i2pIdentKey)
	}
}

// startConfiguredServers starts all enabled server protocols (Onion, I2P, HTTP/HTTPS) with proper coordination.
func startConfiguredServers(c *cli.Context, tlsConfig *tlsConfiguration, i2pkey i2pkeys.I2PKeys, reseeder *reseed.ReseederImpl) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	errChan := make(chan error, 3) // Buffer for up to 3 server errors

	// Start onion server if enabled
	if c.Bool("onion") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lgr.WithField("service", "onion").Debug("Onion server starting")
			if err := reseedOnionWithContext(ctx, c, tlsConfig.onionTlsCert, tlsConfig.onionTlsKey, reseeder); err != nil {
				select {
				case errChan <- fmt.Errorf("onion server error: %w", err):
				default:
				}
			}
		}()
	}

	// Start I2P server if enabled
	if c.Bool("i2p") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lgr.WithField("service", "i2p").Debug("I2P server starting")
			if err := reseedI2PWithContext(ctx, c, tlsConfig.i2pTlsCert, tlsConfig.i2pTlsKey, i2pkey, reseeder); err != nil {
				select {
				case errChan <- fmt.Errorf("i2p server error: %w", err):
				default:
				}
			}
		}()
	}

	// Start HTTP/HTTPS server
	wg.Add(1)
	go func() {
		defer wg.Done()
		if !c.Bool("trustProxy") {
			lgr.WithField("service", "https").Debug("HTTPS server starting")
			if err := reseedHTTPSWithContext(ctx, c, tlsConfig.tlsCert, tlsConfig.tlsKey, reseeder); err != nil {
				select {
				case errChan <- fmt.Errorf("https server error: %w", err):
				default:
				}
			}
		} else {
			lgr.WithField("service", "http").Debug("HTTP server starting")
			if err := reseedHTTPWithContext(ctx, c, reseeder); err != nil {
				select {
				case errChan <- fmt.Errorf("http server error: %w", err):
				default:
				}
			}
		}
	}()

	// Wait for first error or all servers to complete
	go func() {
		wg.Wait()
		close(errChan)
	}()

	// Handle the first error that occurs
	if err := <-errChan; err != nil {
		lgr.WithError(err).Fatal("Fatal server error")
	}
}

func reseedHTTPS(c *cli.Context, tlsCert, tlsKey string, reseeder *reseed.ReseederImpl) {
	server := reseed.NewServer(c.String("prefix"), c.Bool("trustProxy"))
	server.Reseeder = reseeder
	server.RequestRateLimit = c.Int("ratelimit")
	server.WebRateLimit = c.Int("ratelimitweb")
	server.Addr = net.JoinHostPort(c.String("ip"), c.String("port"))

	// load a blacklist
	blacklist := reseed.NewBlacklist()
	server.Blacklist = blacklist
	blacklistFile := c.String("blacklist")
	if "" != blacklistFile {
		blacklist.LoadFile(blacklistFile)
	}

	// print stats once in a while
	if c.Duration("stats") != 0 {
		go func() {
			var mem runtime.MemStats
			for range time.Tick(c.Duration("stats")) {
				runtime.ReadMemStats(&mem)
				lgr.WithField("total_allocs_kb", mem.TotalAlloc/1024).WithField("allocs_kb", mem.Alloc/1024).WithField("mallocs", mem.Mallocs).WithField("num_gc", mem.NumGC).Debug("Memory stats")
			}
		}()
	}
	lgr.WithField("address", server.Addr).Debug("HTTPS server started")
	if err := server.ListenAndServeTLS(tlsCert, tlsKey); err != nil {
		lgr.WithError(err).Fatal("Fatal error")
	}
}

func reseedHTTP(c *cli.Context, reseeder *reseed.ReseederImpl) {
	server := reseed.NewServer(c.String("prefix"), c.Bool("trustProxy"))
	server.RequestRateLimit = c.Int("ratelimit")
	server.WebRateLimit = c.Int("ratelimitweb")
	server.Reseeder = reseeder
	server.Addr = net.JoinHostPort(c.String("ip"), c.String("port"))

	// load a blacklist
	blacklist := reseed.NewBlacklist()
	server.Blacklist = blacklist
	blacklistFile := c.String("blacklist")
	if "" != blacklistFile {
		blacklist.LoadFile(blacklistFile)
	}

	// print stats once in a while
	if c.Duration("stats") != 0 {
		go func() {
			var mem runtime.MemStats
			for range time.Tick(c.Duration("stats")) {
				runtime.ReadMemStats(&mem)
				lgr.WithField("total_allocs_kb", mem.TotalAlloc/1024).WithField("allocs_kb", mem.Alloc/1024).WithField("mallocs", mem.Mallocs).WithField("num_gc", mem.NumGC).Debug("Memory stats")
			}
		}()
	}
	lgr.WithField("address", server.Addr).Debug("HTTP server started")
	if err := server.ListenAndServe(); err != nil {
		lgr.WithError(err).Fatal("Fatal error")
	}
}

func reseedOnion(c *cli.Context, onionTlsCert, onionTlsKey string, reseeder *reseed.ReseederImpl) {
	server := reseed.NewServer(c.String("prefix"), c.Bool("trustProxy"))
	server.Reseeder = reseeder
	server.Addr = net.JoinHostPort(c.String("ip"), c.String("port"))

	// load a blacklist
	blacklist := reseed.NewBlacklist()
	server.Blacklist = blacklist
	blacklistFile := c.String("blacklist")
	if "" != blacklistFile {
		blacklist.LoadFile(blacklistFile)
	}

	// print stats once in a while
	if c.Duration("stats") != 0 {
		go func() {
			var mem runtime.MemStats
			for range time.Tick(c.Duration("stats")) {
				runtime.ReadMemStats(&mem)
				lgr.WithField("total_allocs_kb", mem.TotalAlloc/1024).WithField("allocs_kb", mem.Alloc/1024).WithField("mallocs", mem.Mallocs).WithField("num_gc", mem.NumGC).Debug("Memory stats")
			}
		}()
	}
	port, err := strconv.Atoi(c.String("port"))
	if err != nil {
		lgr.WithError(err).Fatal("Fatal error")
	}
	port += 1
	if _, err := os.Stat(c.String("onionKey")); err == nil {
		ok, err := ioutil.ReadFile(c.String("onionKey"))
		if err != nil {
			lgr.WithError(err).Fatal("Fatal error")
		} else {
			if onionTlsCert != "" && onionTlsKey != "" {
				tlc := &tor.ListenConf{
					LocalPort:    port,
					Key:          ed25519.PrivateKey(ok),
					RemotePorts:  []int{443},
					Version3:     true,
					NonAnonymous: c.Bool("singleOnion"),
					DiscardKey:   false,
				}
				if err := server.ListenAndServeOnionTLS(nil, tlc, onionTlsCert, onionTlsKey); err != nil {
					lgr.WithError(err).Fatal("Fatal error")
				}
			} else {
				tlc := &tor.ListenConf{
					LocalPort:    port,
					Key:          ed25519.PrivateKey(ok),
					RemotePorts:  []int{80},
					Version3:     true,
					NonAnonymous: c.Bool("singleOnion"),
					DiscardKey:   false,
				}
				if err := server.ListenAndServeOnion(nil, tlc); err != nil {
					lgr.WithError(err).Fatal("Fatal error")
				}

			}
		}
	} else if os.IsNotExist(err) {
		tlc := &tor.ListenConf{
			LocalPort:    port,
			RemotePorts:  []int{80},
			Version3:     true,
			NonAnonymous: c.Bool("singleOnion"),
			DiscardKey:   false,
		}
		if err := server.ListenAndServeOnion(nil, tlc); err != nil {
			lgr.WithError(err).Fatal("Fatal error")
		}
	}
	lgr.WithField("address", server.Addr).Debug("Onion server started")
}

func reseedI2P(c *cli.Context, i2pTlsCert, i2pTlsKey string, i2pIdentKey i2pkeys.I2PKeys, reseeder *reseed.ReseederImpl) {
	server := reseed.NewServer(c.String("prefix"), c.Bool("trustProxy"))
	server.RequestRateLimit = c.Int("ratelimit")
	server.WebRateLimit = c.Int("ratelimitweb")
	server.Reseeder = reseeder
	server.Addr = net.JoinHostPort(c.String("ip"), c.String("port"))

	// load a blacklist
	blacklist := reseed.NewBlacklist()
	server.Blacklist = blacklist
	blacklistFile := c.String("blacklist")
	if "" != blacklistFile {
		blacklist.LoadFile(blacklistFile)
	}

	// print stats once in a while
	if c.Duration("stats") != 0 {
		go func() {
			var mem runtime.MemStats
			for range time.Tick(c.Duration("stats")) {
				runtime.ReadMemStats(&mem)
				lgr.WithField("total_allocs_kb", mem.TotalAlloc/1024).WithField("allocs_kb", mem.Alloc/1024).WithField("mallocs", mem.Mallocs).WithField("num_gc", mem.NumGC).Debug("Memory stats")
			}
		}()
	}
	port, err := strconv.Atoi(c.String("port"))
	if err != nil {
		lgr.WithError(err).Fatal("Fatal error")
	}
	port += 1
	if i2pTlsCert != "" && i2pTlsKey != "" {
		if err := server.ListenAndServeI2PTLS(c.String("samaddr"), i2pIdentKey, i2pTlsCert, i2pTlsKey); err != nil {
			lgr.WithError(err).Fatal("Fatal error")
		}
	} else {
		if err := server.ListenAndServeI2P(c.String("samaddr"), i2pIdentKey); err != nil {
			lgr.WithError(err).Fatal("Fatal error")
		}
	}

	lgr.WithField("address", server.Addr).Debug("Onion server started")
}

func getSupplementalNetDb(remote, password, path, samaddr string) {
	log.Println("Remote NetDB Update Loop")
	for {
		if err := downloadRemoteNetDB(remote, password, path, samaddr); err != nil {
			log.Println("Error downloading remote netDb", err)
			time.Sleep(time.Second * 30)
		} else {
			log.Println("Success downloading remote netDb", err)
			time.Sleep(time.Minute * 30)
		}
	}
}

func downloadRemoteNetDB(remote, password, path, samaddr string) error {
	var hremote string
	if !strings.HasPrefix("http://", remote) && !strings.HasPrefix("https://", remote) {
		hremote = "http://" + remote
	}
	if !strings.HasSuffix(hremote, ".tar.gz") {
		hremote += "/netDb.tar.gz"
	}
	url, err := url.Parse(hremote)
	if err != nil {
		return err
	}
	httpRequest := http.Request{
		URL:    url,
		Header: http.Header{},
	}
	garlic, err := onramp.NewGarlic("reseed-client", samaddr, onramp.OPT_WIDE)
	if err != nil {
		return err
	}

	defer garlic.Close()
	httpRequest.Header.Add(http.CanonicalHeaderKey("reseed-password"), password)
	httpRequest.Header.Add(http.CanonicalHeaderKey("x-user-agent"), reseed.I2pUserAgent)
	transport := http.Transport{
		Dial: garlic.Dial,
	}
	client := http.Client{
		Transport: &transport,
	}
	if resp, err := client.Do(&httpRequest); err != nil {
		return err
	} else {
		if bodyBytes, err := ioutil.ReadAll(resp.Body); err != nil {
			return err
		} else {
			if err := ioutil.WriteFile("netDb.tar.gz", bodyBytes, 0o644); err != nil {
				return err
			} else {
				dbPath := filepath.Join(path, "reseed-netDb")
				if err := untar.UntarFile("netDb.tar.gz", dbPath); err != nil {
					return err
				} else {
					// For example...
					opt := copy.Options{
						Skip: func(info os.FileInfo, src, dest string) (bool, error) {
							srcBase := filepath.Base(src)
							dstBase := filepath.Base(dest)
							if info.IsDir() {
								return false, nil
							}
							if srcBase == dstBase {
								log.Println("Ignoring existing RI", srcBase, dstBase)
								return true, nil
							}
							return false, nil
						},
					}
					if err := copy.Copy(dbPath, path, opt); err != nil {
						return err
					} else {
						if err := os.RemoveAll(dbPath); err != nil {
							return err
						} else {
							if err := os.RemoveAll("netDb.tar.gz"); err != nil {
								return err
							}
							return nil
						}
					}
				}
			}
		}
	}
}
