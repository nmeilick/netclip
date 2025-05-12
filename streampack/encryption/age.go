package encryption

import (
	"io"

	"filippo.io/age"
)

// AgeEncryptor implements the Encryptor interface using AGE encryption
type AgeEncryptor struct{}

// NewAgeEncryptor creates a new AGE encryptor
func NewAgeEncryptor() *AgeEncryptor {
	return &AgeEncryptor{}
}

// Encrypt returns an AGE writer
func (e *AgeEncryptor) Encrypt(w io.Writer, password string) (io.WriteCloser, error) {
	// Create a recipient that will encrypt to the password
	recipient, err := age.NewScryptRecipient(password)
	if err != nil {
		return nil, err
	}

	// Set work factor for scrypt
	recipient.SetWorkFactor(15)

	// Create the encryptor
	ageWriter, err := age.Encrypt(w, recipient)
	if err != nil {
		return nil, err
	}

	return ageWriter, nil
}

// Decrypt returns an AGE reader
func (e *AgeEncryptor) Decrypt(r io.Reader, password string) (io.ReadCloser, error) {
	// Create an identity that will decrypt using the password
	identity, err := age.NewScryptIdentity(password)
	if err != nil {
		return nil, err
	}

	// Decrypt the data
	ageReader, err := age.Decrypt(r, identity)
	if err != nil {
		return nil, err
	}

	// Wrap the reader with NopCloser to implement io.ReadCloser
	return io.NopCloser(ageReader), nil
}
