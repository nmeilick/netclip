package streampack

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/argon2"
)

// PasswordVerificationParams defines the parameters for password verification
type PasswordVerificationParams struct {
	// Time cost parameter (number of iterations)
	Iterations uint32
	// Memory cost parameter in KiB
	Memory uint32
	// Number of threads to use
	Threads uint8
	// Length of the derived key
	KeyLength uint32
}

// DefaultVerificationParams returns the default parameters for password verification
func DefaultVerificationParams() PasswordVerificationParams {
	return PasswordVerificationParams{
		Iterations: 1,         // Low iteration count for quick verification
		Memory:     64 * 1024, // 64MB
		Threads:    4,
		KeyLength:  32,
	}
}

// GenerateVerificationData generates salt and verification key for a password
func GenerateVerificationData(password string, params PasswordVerificationParams) (salt []byte, verificationKey []byte, err error) {
	// Generate random salt
	salt = make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive verification key using Argon2id
	verificationKey = argon2.IDKey(
		[]byte(password),
		salt,
		params.Iterations,
		params.Memory,
		params.Threads,
		params.KeyLength,
	)

	return salt, verificationKey, nil
}

// VerifyPassword checks if a password matches the stored verification data
func VerifyPassword(password string, salt, storedKey []byte, params PasswordVerificationParams) bool {
	// Derive verification key using same parameters
	testKey := argon2.IDKey(
		[]byte(password),
		salt,
		params.Iterations,
		params.Memory,
		params.Threads,
		params.KeyLength,
	)

	// Use constant-time comparison to prevent timing attacks
	return bytes.Equal(testKey, storedKey)
}
