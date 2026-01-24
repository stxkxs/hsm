package hsm

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"
)

// ToBase64 encodes bytes to base64.
func ToBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// FromBase64 decodes base64 to bytes.
func FromBase64(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

// IsBase64 checks if a string is valid base64.
func IsBase64(s string) bool {
	if s == "" {
		return true
	}
	if len(s)%4 != 0 {
		return false
	}
	pattern := regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
	return pattern.MatchString(s)
}

// ToHex encodes bytes to hex.
func ToHex(data []byte) string {
	return hex.EncodeToString(data)
}

// FromHex decodes hex to bytes.
func FromHex(data string) ([]byte, error) {
	data = strings.TrimPrefix(data, "0x")
	return hex.DecodeString(data)
}

// NormalizeToBase64 normalizes data to base64 for API requests.
func NormalizeToBase64(data []byte) string {
	return ToBase64(data)
}

// NormalizeStringToBase64 normalizes a string to base64.
func NormalizeStringToBase64(data string) string {
	if IsBase64(data) {
		return data
	}
	return ToBase64([]byte(data))
}

// SHA256 hashes data using SHA-256.
func SHA256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// SHA384 hashes data using SHA-384.
func SHA384(data []byte) []byte {
	hash := sha512.Sum384(data)
	return hash[:]
}

// SHA512 hashes data using SHA-512.
func SHA512Hash(data []byte) []byte {
	hash := sha512.Sum512(data)
	return hash[:]
}

// HMACSHA256 computes HMAC-SHA256.
func HMACSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// ConstantTimeEqual compares two byte slices in constant time.
func ConstantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// RandomBytes generates cryptographically secure random bytes.
func RandomBytes(n int) ([]byte, error) {
	bytes := make([]byte, n)
	_, err := rand.Read(bytes)
	return bytes, err
}

// ConcatBytes concatenates multiple byte slices.
func ConcatBytes(slices ...[]byte) []byte {
	totalLen := 0
	for _, s := range slices {
		totalLen += len(s)
	}
	result := make([]byte, 0, totalLen)
	for _, s := range slices {
		result = append(result, s...)
	}
	return result
}

// DERToRaw converts signature format from DER to raw (R || S).
func DERToRaw(derSignature []byte) ([]byte, error) {
	if len(derSignature) == 0 || derSignature[0] != 0x30 {
		// Already in raw format or invalid
		return derSignature, nil
	}

	offset := 2 // Skip 0x30 and length byte

	// Parse R
	if derSignature[offset] != 0x02 {
		return nil, NewValidationError("Invalid DER signature", "")
	}
	offset++
	rLen := int(derSignature[offset])
	offset++
	r := derSignature[offset : offset+rLen]
	offset += rLen

	// Parse S
	if derSignature[offset] != 0x02 {
		return nil, NewValidationError("Invalid DER signature", "")
	}
	offset++
	sLen := int(derSignature[offset])
	offset++
	s := derSignature[offset : offset+sLen]

	// Remove leading zeros if present
	if len(r) > 32 && r[0] == 0x00 {
		r = r[1:]
	}
	if len(s) > 32 && s[0] == 0x00 {
		s = s[1:]
	}

	// Pad to 32 bytes each
	rPadded := make([]byte, 32)
	sPadded := make([]byte, 32)
	copy(rPadded[32-len(r):], r)
	copy(sPadded[32-len(s):], s)

	return ConcatBytes(rPadded, sPadded), nil
}

// RawToDER converts signature format from raw (R || S) to DER.
func RawToDER(rawSignature []byte) ([]byte, error) {
	if len(rawSignature) != 64 {
		// Might already be DER or invalid
		return rawSignature, nil
	}

	r := rawSignature[:32]
	s := rawSignature[32:64]

	// Remove leading zeros
	for len(r) > 1 && r[0] == 0x00 && r[1]&0x80 == 0 {
		r = r[1:]
	}
	for len(s) > 1 && s[0] == 0x00 && s[1]&0x80 == 0 {
		s = s[1:]
	}

	// Add leading zero if high bit is set
	if r[0]&0x80 != 0 {
		r = append([]byte{0x00}, r...)
	}
	if s[0]&0x80 != 0 {
		s = append([]byte{0x00}, s...)
	}

	totalLen := 4 + len(r) + len(s)

	result := make([]byte, 0, 2+totalLen)
	result = append(result, 0x30, byte(totalLen))
	result = append(result, 0x02, byte(len(r)))
	result = append(result, r...)
	result = append(result, 0x02, byte(len(s)))
	result = append(result, s...)

	return result, nil
}
