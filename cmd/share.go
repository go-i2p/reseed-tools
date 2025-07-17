package cmd

import (

	//"flag"

	"archive/tar"
	"bytes"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/go-i2p/checki2cp/getmeanetdb"
	"github.com/go-i2p/onramp"
)

// NewShareCommand creates a new CLI command for sharing the netDb over I2P with password protection.
// This command sets up a secure file sharing server that allows remote I2P routers to access
// and download router information from the local netDb directory for network synchronization.
// Can be used to combine the local netDb with the netDb of a remote I2P router.
func NewShareCommand() *cli.Command {
	ndb, err := getmeanetdb.WhereIstheNetDB()
	if err != nil {
		log.Fatal(err)
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

// sharer implements a password-protected HTTP file server for netDb sharing.
// It wraps the standard HTTP file system with authentication middleware to ensure
// only authorized clients can access router information over the I2P network.
type sharer struct {
	http.FileSystem
	http.Handler
	Path     string
	Password string
}

func (s *sharer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Extract password from custom reseed-password header
	p, ok := r.Header[http.CanonicalHeaderKey("reseed-password")]
	if !ok {
		return
	}
	if p[0] != s.Password {
		return
	}
	log.Println("Path", r.URL.Path)
	if strings.HasSuffix(r.URL.Path, "tar.gz") {
		log.Println("Serving netdb")
		archive, err := walker(s.Path)
		if err != nil {
			return
		}
		w.Write(archive.Bytes())
		return
	}
	s.Handler.ServeHTTP(w, r)
}

// Sharer creates a new HTTP file server for sharing netDb files over I2P.
// It sets up a password-protected file system server that can serve router information
// to other I2P nodes. The netDbDir parameter specifies the directory containing router files.
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

func shareAction(c *cli.Context) error {
	// Convert netDb path to absolute path for consistent file access
	netDbDir, err := filepath.Abs(c.String("netdb"))
	if err != nil {
		return err
	}
	// Create password-protected file server for netDb sharing
	httpFs := Sharer(netDbDir, c.String("share-password"))
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

	// Start HTTP server over I2P network
	return http.Serve(garlicListener, httpFs)
}

// walker creates a tar archive of all files in the specified netDb directory.
// This function recursively traverses the directory structure and packages all router
// information files into a compressed tar format for efficient network transfer.
func walker(netDbDir string) (*bytes.Buffer, error) {
	var buf bytes.Buffer
	// Create tar writer for archive creation
	tw := tar.NewWriter(&buf)
	walkFn := func(path string, info os.FileInfo, err error) error {
		// Handle filesystem errors during directory traversal
		if err != nil {
			return err
		}
		// Skip directories, only process regular files
		if info.Mode().IsDir() {
			return nil
		}
		// Calculate relative path within netDb directory
		new_path := path[len(netDbDir):]
		if len(new_path) == 0 {
			return nil
		}
		// Open file for reading into tar archive
		fr, err := os.Open(path)
		if err != nil {
			return err
		}
		defer fr.Close()
		if h, err := tar.FileInfoHeader(info, new_path); err != nil {
			log.Fatalln(err)
		} else {
			h.Name = new_path
			if err = tw.WriteHeader(h); err != nil {
				log.Fatalln(err)
			}
		}
		if _, err := io.Copy(tw, fr); err != nil {
			log.Fatalln(err)
		}
		return nil
	}
	if err := filepath.Walk(netDbDir, walkFn); err != nil {
		return nil, err
	}
	return &buf, nil
}
