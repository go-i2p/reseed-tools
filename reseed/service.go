package reseed

import (
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash/crc32"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-i2p/common/router_info"
	"i2pgit.org/idk/reseed-tools/su3"
)

// routerInfo holds metadata and content for an individual I2P router information file.
// Contains the router filename, modification time, raw data, and parsed RouterInfo structure
// used for reseed bundle generation and network database management operations.
type routerInfo struct {
	Name    string
	ModTime time.Time
	Data    []byte
	RI      *router_info.RouterInfo
}

// Peer represents a unique identifier for an I2P peer requesting reseed data.
// It is used to generate deterministic, peer-specific SU3 file contents to ensure
// different peers receive different router sets for improved network diversity.
type Peer string

func (p Peer) Hash() int {
	// Generate deterministic hash from peer identifier for consistent SU3 selection
	b := sha256.Sum256([]byte(p))
	c := make([]byte, len(b))
	copy(c, b[:])
	return int(crc32.ChecksumIEEE(c))
}

/*type Reseeder interface {
	// get an su3 file (bytes) for a peer
	PeerSu3Bytes(peer Peer) ([]byte, error)
}*/

// ReseederImpl implements the core reseed service functionality for generating SU3 files.
// It manages router information caching, cryptographic signing, and periodic rebuilding of
// reseed data to provide fresh router information to bootstrapping I2P nodes. The service
// maintains multiple pre-built SU3 files to efficiently serve concurrent requests.
type ReseederImpl struct {
	// netdb provides access to the local router information database
	netdb *LocalNetDbImpl
	// su3s stores pre-built SU3 files for efficient serving using atomic operations
	su3s atomic.Value // stores [][]byte

	// SigningKey contains the RSA private key for SU3 file cryptographic signing
	SigningKey *rsa.PrivateKey
	// SignerID contains the identity string used in SU3 signature verification
	SignerID []byte
	// NumRi specifies the number of router infos to include in each SU3 file
	NumRi int
	// RebuildInterval determines how often to refresh the SU3 file cache
	RebuildInterval time.Duration
	// NumSu3 specifies the number of pre-built SU3 files to maintain
	NumSu3 int
}

// NewReseeder creates a new reseed service instance with default configuration.
// It initializes the service with standard parameters: 77 router infos per SU3 file
// and 90-hour rebuild intervals to balance freshness with server performance.
func NewReseeder(netdb *LocalNetDbImpl) *ReseederImpl {
	rs := &ReseederImpl{
		netdb:           netdb,
		NumRi:           77,
		RebuildInterval: 90 * time.Hour,
	}
	// Initialize with empty slice to prevent nil panics
	rs.su3s.Store([][]byte{})
	return rs
}

func (rs *ReseederImpl) Start() chan bool {
	// No need for atomic swapper - atomic.Value handles concurrency

	// init the cache
	err := rs.rebuild()
	if nil != err {
		lgr.WithError(err).Error("Error during initial rebuild")
	}

	ticker := time.NewTicker(rs.RebuildInterval)
	quit := make(chan bool)
	go func() {
		for {
			select {
			case <-ticker.C:
				err := rs.rebuild()
				if nil != err {
					lgr.WithError(err).Error("Error during periodic rebuild")
				}
			case <-quit:
				ticker.Stop()
				return
			}
		}
	}()

	return quit
}

func (rs *ReseederImpl) rebuild() error {
	lgr.WithField("operation", "rebuild").Debug("Rebuilding su3 cache...")

	// get all RIs from netdb provider
	ris, err := rs.netdb.RouterInfos()
	if nil != err {
		return fmt.Errorf("unable to get routerInfos: %s", err)
	}

	// use only 75% of routerInfos
	ris = ris[len(ris)/4:]

	// fail if we don't have enough RIs to make a single reseed file
	if rs.NumRi > len(ris) {
		return fmt.Errorf("not enough routerInfos - have: %d, need: %d", len(ris), rs.NumRi)
	}

	// build a pipeline ris -> seeds -> su3
	seedsChan := rs.seedsProducer(ris)
	// fan-in multiple builders
	su3Chan := fanIn(rs.su3Builder(seedsChan), rs.su3Builder(seedsChan), rs.su3Builder(seedsChan))

	// read from su3 chan and append to su3s slice
	var newSu3s [][]byte
	for gs := range su3Chan {
		data, err := gs.MarshalBinary()
		if nil != err {
			return err
		}

		newSu3s = append(newSu3s, data)
	}

	// use this new set of su3s
	rs.su3s.Store(newSu3s)

	lgr.WithField("operation", "rebuild").Debug("Done rebuilding.")

	return nil
}

func (rs *ReseederImpl) seedsProducer(ris []routerInfo) <-chan []routerInfo {
	lenRis := len(ris)

	// if NumSu3 is not specified, then we determine the "best" number based on the number of RIs
	var numSu3s int
	if rs.NumSu3 != 0 {
		numSu3s = rs.NumSu3
	} else {
		switch {
		case lenRis > 4000:
			numSu3s = 300
		case lenRis > 3000:
			numSu3s = 200
		case lenRis > 2000:
			numSu3s = 100
		case lenRis > 1000:
			numSu3s = 75
		default:
			numSu3s = 50
		}
	}

	lgr.WithField("su3_count", numSu3s).WithField("routerinfos_per_su3", rs.NumRi).WithField("total_routerinfos", lenRis).Debug("Building su3 files")

	out := make(chan []routerInfo)

	go func() {
		for i := 0; i < numSu3s; i++ {
			var seeds []routerInfo
			unsorted := rand.Perm(lenRis)
			for z := 0; z < rs.NumRi; z++ {
				seeds = append(seeds, ris[unsorted[z]])
			}

			out <- seeds
		}
		close(out)
	}()

	return out
}

func (rs *ReseederImpl) su3Builder(in <-chan []routerInfo) <-chan *su3.File {
	out := make(chan *su3.File)
	go func() {
		for seeds := range in {
			gs, err := rs.createSu3(seeds)
			if nil != err {
				lgr.WithError(err).Error("Error creating su3 file")
				continue
			}

			out <- gs
		}
		close(out)
	}()
	return out
}

func (rs *ReseederImpl) PeerSu3Bytes(peer Peer) ([]byte, error) {
	m := rs.su3s.Load().([][]byte)

	if len(m) == 0 {
		return nil, errors.New("404")
	}

	return m[peer.Hash()%len(m)], nil
}

func (rs *ReseederImpl) createSu3(seeds []routerInfo) (*su3.File, error) {
	su3File := su3.New()
	su3File.FileType = su3.FileTypeZIP
	su3File.ContentType = su3.ContentTypeReseed

	zipped, err := zipSeeds(seeds)
	if nil != err {
		return nil, err
	}
	su3File.Content = zipped

	su3File.SignerID = rs.SignerID
	su3File.Sign(rs.SigningKey)

	return su3File, nil
}

/*type NetDbProvider interface {
	// Get all router infos
	RouterInfos() ([]routerInfo, error)
}*/

// LocalNetDbImpl provides access to the local I2P router information database.
// It manages reading and filtering router info files from the filesystem, applying
// age-based filtering to ensure only recent and valid router information is included
// in reseed packages distributed to new I2P nodes joining the network.
type LocalNetDbImpl struct {
	// Path specifies the filesystem location of the router information database
	Path string
	// MaxRouterInfoAge defines the maximum age for including router info in reseeds
	MaxRouterInfoAge time.Duration
}

// NewLocalNetDb creates a new local router database instance with specified parameters.
// The path should point to an I2P netDb directory containing routerInfo files, and maxAge
// determines how old router information can be before it's excluded from reseed packages.
func NewLocalNetDb(path string, maxAge time.Duration) *LocalNetDbImpl {
	return &LocalNetDbImpl{
		Path:             path,
		MaxRouterInfoAge: maxAge,
	}
}

func (db *LocalNetDbImpl) RouterInfos() (routerInfos []routerInfo, err error) {
	r, _ := regexp.Compile("^routerInfo-[A-Za-z0-9-=~]+.dat$")

	files := make(map[string]os.FileInfo)
	walkpath := func(path string, f os.FileInfo, err error) error {
		if r.MatchString(f.Name()) {
			files[path] = f
		}
		return nil
	}

	filepath.Walk(db.Path, walkpath)

	for path, file := range files {
		riBytes, err := os.ReadFile(path)
		if nil != err {
			lgr.WithError(err).WithField("path", path).Error("Error reading RouterInfo file")
			continue
		}

		// ignore outdate routerInfos
		age := time.Since(file.ModTime())
		if age > db.MaxRouterInfoAge {
			continue
		}
		riStruct, remainder, err := router_info.ReadRouterInfo(riBytes)
		if err != nil {
			lgr.WithError(err).WithField("path", path).Error("RouterInfo Parsing Error")
			lgr.WithField("path", path).WithField("remainder", remainder).Debug("Leftover Data(for debugging)")
			continue
		}

		// skip crappy routerInfos
		if riStruct.Reachable() && riStruct.UnCongested() && riStruct.GoodVersion() {
			routerInfos = append(routerInfos, routerInfo{
				Name:    file.Name(),
				ModTime: file.ModTime(),
				Data:    riBytes,
				RI:      &riStruct,
			})
		} else {
			lgr.WithField("path", path).WithField("capabilities", riStruct.RouterCapabilities()).WithField("version", riStruct.RouterVersion()).Debug("Skipped less-useful RouterInfo")
		}
	}

	return
}

// fanIn multiplexes multiple SU3 file channels into a single output channel.
// This function implements the fan-in concurrency pattern to efficiently merge
// multiple concurrent SU3 file generation streams for balanced load distribution.
func fanIn(inputs ...<-chan *su3.File) <-chan *su3.File {
	out := make(chan *su3.File, len(inputs))

	var wg sync.WaitGroup
	wg.Add(len(inputs))
	go func() {
		// close "out" when we're done
		wg.Wait()
		close(out)
	}()

	// fan-in all the inputs to a single output
	for _, input := range inputs {
		go func(in <-chan *su3.File) {
			defer wg.Done()
			for n := range in {
				out <- n
			}
		}(input)
	}

	return out
}
