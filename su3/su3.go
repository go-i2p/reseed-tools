package su3

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"strconv"
	"time"
)

// Constants moved to constants.go

// File represents a complete SU3 file structure for I2P software distribution.
// SU3 files are cryptographically signed containers used to distribute router updates,
// plugins, reseed data, and other I2P network components. Each file contains metadata,
// content, and a digital signature for verification.
type File struct {
	// Format specifies the SU3 file format version for compatibility tracking
	Format uint8

	// SignatureType indicates the cryptographic signature algorithm used
	// Valid values are defined by Sig* constants (RSA, ECDSA, DSA variants)
	SignatureType uint16

	// FileType specifies the format of the contained data
	// Valid values are defined by FileType* constants (ZIP, XML, HTML, etc.)
	FileType uint8

	// ContentType categorizes the purpose of the contained data
	// Valid values are defined by ContentType* constants (Router, Plugin, Reseed, etc.)
	ContentType uint8

	// Version contains version information as bytes, zero-padded to minimum length
	Version []byte

	// SignerID contains the identity of the entity that signed this file
	SignerID []byte

	// Content holds the actual file payload data to be distributed
	Content []byte

	// Signature contains the cryptographic signature for file verification
	Signature []byte

	// SignedBytes stores the signed portion of the file for verification purposes
	SignedBytes []byte
}

// New creates a new SU3 file with default settings and current timestamp.
// The file is initialized with RSA-SHA512 signature type and a Unix timestamp version.
// Additional fields must be set before signing and distribution.
// New creates a new SU3 file with default settings and current timestamp.
// The file is initialized with RSA-SHA512 signature type and a Unix timestamp version.
// Additional fields must be set before signing and distribution.
func New() *File {
	return &File{
		Version:       []byte(strconv.FormatInt(time.Now().Unix(), 10)),
		SignatureType: SigTypeRSAWithSHA512,
	}
}

// Sign cryptographically signs the SU3 file using the provided RSA private key.
// The signature covers the file header and content but not the signature itself.
// The signature length is automatically determined by the RSA key size.
// Returns an error if the private key is nil or signature generation fails.
func (s *File) Sign(privkey *rsa.PrivateKey) error {
	if privkey == nil {
		lgr.Error("Private key cannot be nil for SU3 signing")
		return fmt.Errorf("private key cannot be nil")
	}

	// Pre-calculate signature length to ensure header consistency
	// This temporary signature ensures BodyBytes() generates correct metadata
	keySize := privkey.Size()           // Returns key size in bytes
	s.Signature = make([]byte, keySize) // Temporary signature with correct length

	var hashType crypto.Hash
	// Select appropriate hash algorithm based on signature type
	// Different signature types require specific hash functions for security
	switch s.SignatureType {
	case SigTypeDSA:
		hashType = crypto.SHA1
	case SigTypeECDSAWithSHA256, SigTypeRSAWithSHA256:
		hashType = crypto.SHA256
	case SigTypeECDSAWithSHA384, SigTypeRSAWithSHA384:
		hashType = crypto.SHA384
	case SigTypeECDSAWithSHA512, SigTypeRSAWithSHA512:
		hashType = crypto.SHA512
	default:
		lgr.WithField("signature_type", s.SignatureType).Error("Unknown signature type for SU3 signing")
		return fmt.Errorf("unknown signature type: %d", s.SignatureType)
	}

	h := hashType.New()
	h.Write(s.BodyBytes())
	digest := h.Sum(nil)

	// Generate RSA signature using PKCS#1 v1.5 padding scheme
	// The hash type is already applied, so we pass 0 to indicate pre-hashed data
	sig, err := rsa.SignPKCS1v15(rand.Reader, privkey, 0, digest)
	if nil != err {
		lgr.WithError(err).Error("Failed to generate RSA signature for SU3 file")
		return err
	}

	s.Signature = sig

	return nil
}

// BodyBytes generates the binary representation of the SU3 file without the signature.
// This includes the magic header, metadata fields, and content data in the proper SU3 format.
// The signature field length is calculated but the actual signature bytes are not included.
// This data is used for signature generation and verification operations.
func (s *File) BodyBytes() []byte {
	var (
		buf = new(bytes.Buffer)

		skip    [1]byte
		bigSkip [12]byte

		versionLength   = uint8(len(s.Version))
		signatureLength = uint16(512)
		signerIDLength  = uint8(len(s.SignerID))
		contentLength   = uint64(len(s.Content))
	)

	// Calculate signature length based on algorithm and available signature data
	// Different signature types have different length requirements for proper verification
	switch s.SignatureType {
	case SigTypeDSA:
		signatureLength = uint16(40)
	case SigTypeECDSAWithSHA256, SigTypeRSAWithSHA256:
		signatureLength = uint16(256)
	case SigTypeECDSAWithSHA384, SigTypeRSAWithSHA384:
		signatureLength = uint16(384)
	case SigTypeECDSAWithSHA512, SigTypeRSAWithSHA512:
		// For RSA, signature length depends on key size, not hash algorithm
		// Use actual signature length if available, otherwise default to 2048-bit RSA
		if len(s.Signature) > 0 {
			signatureLength = uint16(len(s.Signature))
		} else {
			signatureLength = uint16(256) // Default for 2048-bit RSA key
		}
	}

	// Ensure version field meets minimum length requirement by zero-padding
	// SU3 specification requires version fields to be at least minVersionLength bytes
	if len(s.Version) < minVersionLength {
		minBytes := make([]byte, minVersionLength)
		copy(minBytes, s.Version)
		s.Version = minBytes
		versionLength = uint8(len(s.Version))
	}

	// Write SU3 file header in big-endian binary format following specification
	// Each field is written in the exact order and size required by the SU3 format
	binary.Write(buf, binary.BigEndian, []byte(magicBytes))
	binary.Write(buf, binary.BigEndian, skip)
	binary.Write(buf, binary.BigEndian, s.Format)
	binary.Write(buf, binary.BigEndian, s.SignatureType)
	binary.Write(buf, binary.BigEndian, signatureLength)
	binary.Write(buf, binary.BigEndian, skip)
	binary.Write(buf, binary.BigEndian, versionLength)
	binary.Write(buf, binary.BigEndian, skip)
	binary.Write(buf, binary.BigEndian, signerIDLength)
	binary.Write(buf, binary.BigEndian, contentLength)
	binary.Write(buf, binary.BigEndian, skip)
	binary.Write(buf, binary.BigEndian, s.FileType)
	binary.Write(buf, binary.BigEndian, skip)
	binary.Write(buf, binary.BigEndian, s.ContentType)
	binary.Write(buf, binary.BigEndian, bigSkip)
	binary.Write(buf, binary.BigEndian, s.Version)
	binary.Write(buf, binary.BigEndian, s.SignerID)
	binary.Write(buf, binary.BigEndian, s.Content)

	return buf.Bytes()
}

// MarshalBinary serializes the complete SU3 file including signature to binary format.
// This produces the final SU3 file data that can be written to disk or transmitted.
// The signature must be set before calling this method for a valid SU3 file.
func (s *File) MarshalBinary() ([]byte, error) {
	buf := bytes.NewBuffer(s.BodyBytes())

	// Append signature to complete the SU3 file format
	// The signature is always the last component of a valid SU3 file
	binary.Write(buf, binary.BigEndian, s.Signature)

	return buf.Bytes(), nil
}

// UnmarshalBinary deserializes binary data into a SU3 file structure.
// This parses the SU3 file format and populates all fields including header metadata,
// content, and signature. No validation is performed on the parsed data.
func (s *File) UnmarshalBinary(data []byte) error {
	var (
		r = bytes.NewReader(data)

		magic   = []byte(magicBytes)
		skip    [1]byte
		bigSkip [12]byte

		signatureLength uint16
		versionLength   uint8
		signerIDLength  uint8
		contentLength   uint64
	)

	// Read SU3 file header fields in big-endian format
	// Each binary.Read operation should be checked for errors in production code
	binary.Read(r, binary.BigEndian, &magic)
	binary.Read(r, binary.BigEndian, &skip)
	binary.Read(r, binary.BigEndian, &s.Format)
	binary.Read(r, binary.BigEndian, &s.SignatureType)
	binary.Read(r, binary.BigEndian, &signatureLength)
	binary.Read(r, binary.BigEndian, &skip)
	binary.Read(r, binary.BigEndian, &versionLength)
	binary.Read(r, binary.BigEndian, &skip)
	binary.Read(r, binary.BigEndian, &signerIDLength)
	binary.Read(r, binary.BigEndian, &contentLength)
	binary.Read(r, binary.BigEndian, &skip)
	binary.Read(r, binary.BigEndian, &s.FileType)
	binary.Read(r, binary.BigEndian, &skip)
	binary.Read(r, binary.BigEndian, &s.ContentType)
	binary.Read(r, binary.BigEndian, &bigSkip)

	// Allocate byte slices based on header length fields
	// These lengths determine how much data to read for each variable-length field
	s.Version = make([]byte, versionLength)
	s.SignerID = make([]byte, signerIDLength)
	s.Content = make([]byte, contentLength)
	s.Signature = make([]byte, signatureLength)

	// Read variable-length data fields in the order specified by SU3 format
	// Version, SignerID, Content, and Signature follow the fixed header fields
	binary.Read(r, binary.BigEndian, &s.Version)
	binary.Read(r, binary.BigEndian, &s.SignerID)
	binary.Read(r, binary.BigEndian, &s.Content)
	binary.Read(r, binary.BigEndian, &s.Signature)

	return nil
}

// VerifySignature validates the SU3 file signature using the provided certificate.
// This checks that the signature was created by the private key corresponding to the
// certificate's public key. The signature algorithm is determined by the SignatureType field.
// Returns an error if verification fails or the signature type is unsupported.
func (s *File) VerifySignature(cert *x509.Certificate) error {
	var sigAlg x509.SignatureAlgorithm
	// Map SU3 signature types to standard x509 signature algorithms
	// Each SU3 signature type corresponds to a specific combination of algorithm and hash
	switch s.SignatureType {
	case SigTypeDSA:
		sigAlg = x509.DSAWithSHA1
	case SigTypeECDSAWithSHA256:
		sigAlg = x509.ECDSAWithSHA256
	case SigTypeECDSAWithSHA384:
		sigAlg = x509.ECDSAWithSHA384
	case SigTypeECDSAWithSHA512:
		sigAlg = x509.ECDSAWithSHA512
	case SigTypeRSAWithSHA256:
		sigAlg = x509.SHA256WithRSA
	case SigTypeRSAWithSHA384:
		sigAlg = x509.SHA384WithRSA
	case SigTypeRSAWithSHA512:
		sigAlg = x509.SHA512WithRSA
	default:
		lgr.WithField("signature_type", s.SignatureType).Error("Unknown signature type for SU3 verification")
		return fmt.Errorf("unknown signature type: %d", s.SignatureType)
	}

	err := checkSignature(cert, sigAlg, s.BodyBytes(), s.Signature)
	if err != nil {
		lgr.WithError(err).WithField("signature_type", s.SignatureType).Error("SU3 signature verification failed")
		return err
	}

	return nil
}

// String returns a human-readable representation of the SU3 file metadata.
// This includes format information, signature type, file type, content type, version,
// and signer ID in a formatted display suitable for debugging and verification.
func (s *File) String() string {
	var b bytes.Buffer

	// Format SU3 file metadata in a readable table structure
	// Display key fields with proper formatting and null-byte trimming
	fmt.Fprintln(&b, "---------------------------")
	fmt.Fprintf(&b, "Format: %q\n", s.Format)
	fmt.Fprintf(&b, "SignatureType: %q\n", s.SignatureType)
	fmt.Fprintf(&b, "FileType: %q\n", s.FileType)
	fmt.Fprintf(&b, "ContentType: %q\n", s.ContentType)
	fmt.Fprintf(&b, "Version: %q\n", bytes.Trim(s.Version, "\x00"))
	fmt.Fprintf(&b, "SignerId: %q\n", s.SignerID)
	fmt.Fprintf(&b, "---------------------------")

	// Content and signature data are commented out to avoid large output
	// Uncomment these lines for debugging when full content inspection is needed
	// fmt.Fprintf(&b, "Content: %q\n", s.Content)
	// fmt.Fprintf(&b, "Signature: %q\n", s.Signature)
	// fmt.Fprintln(&b, "---------------------------")

	return b.String()
}
