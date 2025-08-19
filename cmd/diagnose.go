package cmd

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/go-i2p/common/router_info"
	"github.com/urfave/cli/v3"
)

// NewDiagnoseCommand creates a new CLI command for diagnosing RouterInfo files
// in the netDb directory to identify corrupted or problematic files that cause
// parsing errors during reseed operations.
func NewDiagnoseCommand() *cli.Command {
	return &cli.Command{
		Name:  "diagnose",
		Usage: "Diagnose RouterInfo files in netDb to identify parsing issues",
		Description: `Scan RouterInfo files in the netDb directory to identify files that cause
parsing errors. This can help identify corrupted files that should be removed
to prevent "mapping format violation" errors during reseed operations.`,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "netdb",
				Aliases:  []string{"n"},
				Usage:    "Path to the netDb directory containing RouterInfo files",
				Value:    findDefaultNetDbPath(),
				Required: false,
			},
			&cli.DurationFlag{
				Name:    "max-age",
				Aliases: []string{"a"},
				Usage:   "Maximum age for RouterInfo files to consider (e.g., 192h for 8 days)",
				Value:   192 * time.Hour, // Default matches reseed server
			},
			&cli.BoolFlag{
				Name:    "remove-bad",
				Aliases: []string{"r"},
				Usage:   "Remove files that fail parsing (use with caution)",
				Value:   false,
			},
			&cli.BoolFlag{
				Name:    "verbose",
				Aliases: []string{"v"},
				Usage:   "Enable verbose output",
				Value:   false,
			},
			&cli.BoolFlag{
				Name:    "debug",
				Aliases: []string{"d"},
				Usage:   "Enable debug mode (sets I2P_DEBUG=true)",
				Value:   false,
			},
		},
		Action: diagnoseRouterInfoFiles,
	}
}

// diagnoseRouterInfoFiles performs the main diagnosis logic for RouterInfo files
func diagnoseRouterInfoFiles(ctx *cli.Context) error {
	netdbPath := ctx.String("netdb")
	maxAge := ctx.Duration("max-age")
	removeBad := ctx.Bool("remove-bad")
	verbose := ctx.Bool("verbose")
	debug := ctx.Bool("debug")

	// Set debug mode if requested
	if debug {
		os.Setenv("I2P_DEBUG", "true")
		fmt.Println("Debug mode enabled (I2P_DEBUG=true)")
	}

	if netdbPath == "" {
		return fmt.Errorf("netDb path is required. Use --netdb flag or ensure I2P is installed in a standard location")
	}

	// Check if netdb directory exists
	if _, err := os.Stat(netdbPath); os.IsNotExist(err) {
		return fmt.Errorf("netDb directory does not exist: %s", netdbPath)
	}

	fmt.Printf("Diagnosing RouterInfo files in: %s\n", netdbPath)
	fmt.Printf("Maximum file age: %v\n", maxAge)
	fmt.Printf("Remove bad files: %v\n", removeBad)
	fmt.Println()

	// Compile regex for RouterInfo files
	routerInfoPattern, err := regexp.Compile(`^routerInfo-[A-Za-z0-9-=~]+\.dat$`)
	if err != nil {
		return fmt.Errorf("failed to compile regex pattern: %v", err)
	}

	var (
		totalFiles     int
		tooOldFiles    int
		corruptedFiles int
		validFiles     int
		removedFiles   int
	)

	// Walk through netDb directory
	err = filepath.WalkDir(netdbPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if verbose {
				fmt.Printf("Error accessing path %s: %v\n", path, err)
			}
			return nil // Continue processing other files
		}

		// Skip directories
		if d.IsDir() {
			return nil
		}

		// Check if file matches RouterInfo pattern
		if !routerInfoPattern.MatchString(d.Name()) {
			return nil
		}

		totalFiles++

		// Get file info
		info, err := d.Info()
		if err != nil {
			if verbose {
				fmt.Printf("Error getting file info for %s: %v\n", path, err)
			}
			return nil
		}

		// Check file age
		age := time.Since(info.ModTime())
		if age > maxAge {
			tooOldFiles++
			if verbose {
				fmt.Printf("SKIP (too old): %s (age: %v)\n", path, age)
			}
			return nil
		}

		// Try to read and parse the file
		routerBytes, err := os.ReadFile(path)
		if err != nil {
			fmt.Printf("ERROR reading %s: %v\n", path, err)
			corruptedFiles++
			return nil
		}

		// Try to parse RouterInfo - using same approach as the reseed server
		riStruct, remainder, err := router_info.ReadRouterInfo(routerBytes)
		if err != nil {
			fmt.Printf("CORRUPTED: %s - %v\n", path, err)
			if len(remainder) > 0 {
				fmt.Printf("  Leftover data: %d bytes\n", len(remainder))
				if verbose {
					maxBytes := len(remainder)
					if maxBytes > 50 {
						maxBytes = 50
					}
					fmt.Printf("  First %d bytes of remainder: %x\n", maxBytes, remainder[:maxBytes])
				}
			}
			corruptedFiles++

			// Remove file if requested
			if removeBad {
				if removeErr := os.Remove(path); removeErr != nil {
					fmt.Printf("  ERROR removing file: %v\n", removeErr)
				} else {
					fmt.Printf("  REMOVED\n")
					removedFiles++
				}
			}
		} else {
			// Perform additional checks that reseed server does
			gv, err := riStruct.GoodVersion()
			if err != nil {
				fmt.Printf("Version check error %s", err)
			}
			if riStruct.Reachable() && riStruct.UnCongested() && gv {
				validFiles++
				if verbose {
					fmt.Printf("OK: %s (reachable, uncongested, good version)\n", path)
				}
			} else {
				validFiles++
				if verbose {
					fmt.Printf("OK: %s (but would be skipped by reseed: reachable=%v uncongested=%v goodversion=%v)\n",
						path, riStruct.Reachable(), riStruct.UnCongested(), gv)
				}
			}
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("error walking netDb directory: %v", err)
	}

	// Print summary
	fmt.Println("\n=== DIAGNOSIS SUMMARY ===")
	fmt.Printf("Total RouterInfo files found: %d\n", totalFiles)
	fmt.Printf("Files too old (skipped): %d\n", tooOldFiles)
	fmt.Printf("Valid files: %d\n", validFiles)
	fmt.Printf("Corrupted files: %d\n", corruptedFiles)
	if removeBad {
		fmt.Printf("Files removed: %d\n", removedFiles)
	}

	if corruptedFiles > 0 {
		fmt.Printf("\nFound %d corrupted RouterInfo files causing parsing errors.\n", corruptedFiles)
		if !removeBad {
			fmt.Println("To remove them, run this command again with --remove-bad flag.")
		}
		fmt.Println("These files are likely causing the 'mapping format violation' errors you're seeing.")
	} else {
		fmt.Println("\nNo corrupted RouterInfo files found. The parsing errors may be transient.")
	}

	return nil
}

// findDefaultNetDbPath attempts to find the default netDb path for the current system
func findDefaultNetDbPath() string {
	// Common I2P netDb locations
	possiblePaths := []string{
		os.ExpandEnv("$HOME/.i2p/netDb"),
		os.ExpandEnv("$HOME/Library/Application Support/i2p/netDb"),
		"/var/lib/i2p/i2p-config/netDb",
		"/usr/share/i2p/netDb",
	}

	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return "" // Return empty if not found
}
