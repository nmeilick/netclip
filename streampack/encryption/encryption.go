package encryption

import (
	"fmt"
	"io"
)

// EncryptionType identifies the encryption algorithm
type EncryptionType string

const (
	AGEEncryption EncryptionType = "age"
)

// Encryptor defines the interface for encryption algorithms
type Encryptor interface {
	Encrypt(w io.Writer, password string) (io.WriteCloser, error)
	Decrypt(r io.Reader, password string) (io.ReadCloser, error)
}

// GetEncryptor returns the appropriate encryptor based on type
func GetEncryptor(encryptionType EncryptionType) (Encryptor, error) {
	switch encryptionType {
	case AGEEncryption:
		return NewAgeEncryptor(), nil
	}
	return nil, fmt.Errorf("unknown encryption type: %q", encryptionType)
}
