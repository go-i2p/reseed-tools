package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"

	"github.com/urfave/cli/v3"
	"i2pgit.org/go-i2p/reseed-tools/reseed"
	"i2pgit.org/go-i2p/reseed-tools/su3"
)

// I2PHome returns the I2P configuration directory path for the current system.
// It checks multiple standard locations including environment variables and default
// directories to locate I2P configuration files and certificates for SU3 verification.
func I2PHome() string {
	// Check I2P environment variable first for custom installations
	envCheck := os.Getenv("I2P")
	if envCheck != "" {
		return envCheck
	}
	// Get current user's home directory for standard I2P paths
	usr, err := user.Current()
	if nil != err {
		panic(err)
	}
	// Check for i2p-config directory (common on Linux distributions)
	sysCheck := filepath.Join(usr.HomeDir, "i2p-config")
	if _, err := os.Stat(sysCheck); nil == err {
		return sysCheck
	}
	// Check for standard i2p directory in user home
	usrCheck := filepath.Join(usr.HomeDir, "i2p")
	if _, err := os.Stat(usrCheck); nil == err {
		return usrCheck
	}
	return ""
}

// NewSu3VerifyCommand creates a new CLI command for verifying SU3 file signatures.
// This command validates the cryptographic integrity of SU3 files using the embedded
// certificates and signatures, ensuring files haven't been tampered with during distribution.
func NewSu3VerifyCommand() *cli.Command {
	return &cli.Command{
		Name:        "verify",
		Usage:       "Verify a Su3 file",
		Description: "Verify a Su3 file",
		Action:      su3VerifyAction,
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "extract",
				Usage: "Also extract the contents of the su3",
			},
			&cli.StringFlag{
				Name:  "signer",
				Value: getDefaultSigner(),
				Usage: "Your su3 signing ID (ex. something@mail.i2p)",
			},
			&cli.StringFlag{
				Name:  "keystore",
				Value: filepath.Join(I2PHome(), "/certificates/reseed"),
				Usage: "Path to the keystore",
			},
		},
	}
}

func su3VerifyAction(c *cli.Context) error {
	su3File := su3.New()

	data, err := ioutil.ReadFile(c.Args().Get(0))
	if nil != err {
		return err
	}
	if err := su3File.UnmarshalBinary(data); err != nil {
		return err
	}

	fmt.Println(su3File.String())
	absPath, err := filepath.Abs(c.String("keystore"))
	if nil != err {
		return err
	}
	keyStorePath := filepath.Dir(absPath)
	reseedDir := filepath.Base(absPath)

	// get the reseeder key
	ks := reseed.KeyStore{Path: keyStorePath}

	if c.String("signer") != "" {
		su3File.SignerID = []byte(c.String("signer"))
	}
	lgr.WithField("keystore", absPath).WithField("purpose", reseedDir).WithField("signer", string(su3File.SignerID)).Debug("Using keystore")

	cert, err := ks.DirReseederCertificate(reseedDir, su3File.SignerID)
	if nil != err {
		fmt.Println(err)
		return err
	}

	if err := su3File.VerifySignature(cert); nil != err {
		return err
	}

	fmt.Printf("Signature is valid for signer '%s'\n", su3File.SignerID)

	if c.Bool("extract") {
		// @todo: don't assume zip
		ioutil.WriteFile("extracted.zip", su3File.BodyBytes(), 0o755)
	}
	return nil
}
