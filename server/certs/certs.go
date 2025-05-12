package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nmeilick/netclip/common"
	"github.com/nmeilick/netclip/server/config"
	"github.com/urfave/cli/v2"
)

// Commands returns the CLI commands for certificate management
func Commands() *cli.Command {
	return &cli.Command{
		Name:  "certs",
		Usage: "Manage TLS certificates",
		Subcommands: []*cli.Command{
			{
				Name:  "create-ca",
				Usage: "Create a Certificate Authority",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "output-dir",
						Aliases: []string{"o"},
						Usage:   "Output directory for CA files",
						Value:   "ca",
					},
					&cli.StringFlag{
						Name:    "common-name",
						Aliases: []string{"cn"},
						Usage:   "Common Name for the CA",
						Value:   "QCopy Root CA",
					},
					&cli.StringFlag{
						Name:    "organization",
						Aliases: []string{"org"},
						Usage:   "Organization name",
						Value:   "QCopy",
					},
					&cli.IntFlag{
						Name:  "key-size",
						Usage: "RSA key size in bits",
						Value: 4096,
					},
					&cli.IntFlag{
						Name:  "validity",
						Usage: "Validity period in days",
						Value: 3650, // 10 years
					},
					&cli.BoolFlag{
						Name:    "force",
						Aliases: []string{"f"},
						Usage:   "Overwrite existing files",
					},
				},
				Action: func(c *cli.Context) error {
					return createCA(c)
				},
			},
			{
				Name:  "create-cert",
				Usage: "Create a server certificate signed by the CA",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "ca-cert",
						Usage: "Path to CA certificate",
						Value: "ca/ca.crt",
					},
					&cli.StringFlag{
						Name:  "ca-key",
						Usage: "Path to CA private key",
						Value: "ca/ca.key",
					},
					&cli.StringFlag{
						Name:    "output-dir",
						Aliases: []string{"o"},
						Usage:   "Output directory for certificate files",
						Value:   "certs",
					},
					&cli.StringFlag{
						Name:    "common-name",
						Aliases: []string{"cn"},
						Usage:   "Common Name for the certificate",
						Value:   "localhost",
					},
					&cli.StringSliceFlag{
						Name:  "dns",
						Usage: "DNS Subject Alternative Names",
						Value: cli.NewStringSlice("localhost"),
					},
					&cli.StringSliceFlag{
						Name:  "ip",
						Usage: "IP Subject Alternative Names",
						Value: cli.NewStringSlice("127.0.0.1"),
					},
					&cli.StringFlag{
						Name:    "organization",
						Aliases: []string{"org"},
						Usage:   "Organization name",
						Value:   "QCopy",
					},
					&cli.IntFlag{
						Name:  "key-size",
						Usage: "RSA key size in bits",
						Value: 2048,
					},
					&cli.IntFlag{
						Name:  "validity",
						Usage: "Validity period in days",
						Value: 365, // 1 year
					},
					&cli.BoolFlag{
						Name:    "force",
						Aliases: []string{"f"},
						Usage:   "Overwrite existing files",
					},
				},
				Action: func(c *cli.Context) error {
					return createCert(c)
				},
			},
			{
				Name:  "create-client-cert",
				Usage: "Create a client certificate signed by the CA",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "ca-cert",
						Usage: "Path to CA certificate",
						Value: "ca/ca.crt",
					},
					&cli.StringFlag{
						Name:  "ca-key",
						Usage: "Path to CA private key",
						Value: "ca/ca.key",
					},
					&cli.StringFlag{
						Name:    "output-dir",
						Aliases: []string{"o"},
						Usage:   "Output directory for certificate files",
						Value:   "clients",
					},
					&cli.StringFlag{
						Name:     "name",
						Aliases:  []string{"n"},
						Usage:    "Client name (used for filename and Common Name)",
						Required: true,
					},
					&cli.StringFlag{
						Name:    "organization",
						Aliases: []string{"org"},
						Usage:   "Organization name",
						Value:   "QCopy Client",
					},
					&cli.IntFlag{
						Name:  "key-size",
						Usage: "RSA key size in bits",
						Value: 2048,
					},
					&cli.IntFlag{
						Name:  "validity",
						Usage: "Validity period in days",
						Value: 365, // 1 year
					},
					&cli.BoolFlag{
						Name:    "force",
						Aliases: []string{"f"},
						Usage:   "Overwrite existing files",
					},
				},
				Action: func(c *cli.Context) error {
					return createClientCert(c)
				},
			},
			{
				Name:  "create-self-signed",
				Usage: "Create a self-signed certificate",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "output-dir",
						Aliases: []string{"o"},
						Usage:   "Output directory for certificate files",
						Value:   "certs",
					},
					&cli.StringFlag{
						Name:    "common-name",
						Aliases: []string{"cn"},
						Usage:   "Common Name for the certificate",
						Value:   "localhost",
					},
					&cli.StringSliceFlag{
						Name:  "dns",
						Usage: "DNS Subject Alternative Names",
						Value: cli.NewStringSlice("localhost"),
					},
					&cli.StringSliceFlag{
						Name:  "ip",
						Usage: "IP Subject Alternative Names",
						Value: cli.NewStringSlice("127.0.0.1"),
					},
					&cli.StringFlag{
						Name:    "organization",
						Aliases: []string{"org"},
						Usage:   "Organization name",
						Value:   "QCopy",
					},
					&cli.IntFlag{
						Name:  "key-size",
						Usage: "RSA key size in bits",
						Value: 2048,
					},
					&cli.IntFlag{
						Name:  "validity",
						Usage: "Validity period in days",
						Value: 365, // 1 year
					},
					&cli.BoolFlag{
						Name:    "force",
						Aliases: []string{"f"},
						Usage:   "Overwrite existing files",
					},
				},
				Action: func(c *cli.Context) error {
					return createSelfSignedCert(c)
				},
			},
		},
	}
}

// createCA creates a new Certificate Authority
func createCA(c *cli.Context) error {
	outputDir := c.String("output-dir")
	commonName := c.String("common-name")
	organization := c.String("organization")
	keySize := c.Int("key-size")
	validityDays := c.Int("validity")
	force := c.Bool("force")

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Check if files already exist
	certPath := filepath.Join(outputDir, "ca.crt")
	keyPath := filepath.Join(outputDir, "ca.key")

	if !force {
		if _, err := os.Stat(certPath); err == nil {
			return fmt.Errorf("certificate file already exists: %s (use --force to overwrite)", certPath)
		}
		if _, err := os.Stat(keyPath); err == nil {
			return fmt.Errorf("key file already exists: %s (use --force to overwrite)", keyPath)
		}
	}

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(validityDays) * 24 * time.Hour)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{organization},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	// Create certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Write certificate to file
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to open certificate file for writing: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("failed to write certificate to file: %w", err)
	}

	// Write private key to file
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open key file for writing: %w", err)
	}
	defer keyOut.Close()

	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("failed to write key to file: %w", err)
	}

	fmt.Printf("CA certificate created successfully:\n")
	fmt.Printf("  - Certificate: %s\n", certPath)
	fmt.Printf("  - Private key: %s\n", keyPath)
	fmt.Printf("  - Validity: %d days (until %s)\n", validityDays, notAfter.Format("2006-01-02"))

	return nil
}

// createCert creates a new server certificate signed by the CA
func createCert(c *cli.Context) error {
	caCertPath := c.String("ca-cert")
	caKeyPath := c.String("ca-key")
	outputDir := c.String("output-dir")
	commonName := c.String("common-name")
	dnsNames := c.StringSlice("dns")
	ipAddresses := c.StringSlice("ip")
	organization := c.String("organization")
	keySize := c.Int("key-size")
	validityDays := c.Int("validity")
	force := c.Bool("force")

	// Load CA certificate and key
	caCert, caKey, err := loadCA(caCertPath, caKeyPath)
	if err != nil {
		return err
	}

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Check if files already exist
	certPath := filepath.Join(outputDir, "server.crt")
	keyPath := filepath.Join(outputDir, "server.key")

	if !force {
		if _, err := os.Stat(certPath); err == nil {
			return fmt.Errorf("certificate file already exists: %s (use --force to overwrite)", certPath)
		}
		if _, err := os.Stat(keyPath); err == nil {
			return fmt.Errorf("key file already exists: %s (use --force to overwrite)", keyPath)
		}
	}

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Parse IP addresses
	var ips []net.IP
	for _, ip := range ipAddresses {
		if ip != "" {
			ips = append(ips, net.ParseIP(ip))
		}
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(validityDays) * 24 * time.Hour)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{organization},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}

	// Create certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &privateKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Write certificate to file
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to open certificate file for writing: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("failed to write certificate to file: %w", err)
	}

	// Write private key to file
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open key file for writing: %w", err)
	}
	defer keyOut.Close()

	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("failed to write key to file: %w", err)
	}

	fmt.Printf("Server certificate created successfully:\n")
	fmt.Printf("  - Certificate: %s\n", certPath)
	fmt.Printf("  - Private key: %s\n", keyPath)
	fmt.Printf("  - Common Name: %s\n", commonName)
	fmt.Printf("  - DNS Names: %s\n", strings.Join(dnsNames, ", "))
	fmt.Printf("  - IP Addresses: %s\n", strings.Join(ipAddresses, ", "))
	fmt.Printf("  - Validity: %d days (until %s)\n", validityDays, notAfter.Format("2006-01-02"))

	return nil
}

// createClientCert creates a new client certificate signed by the CA
func createClientCert(c *cli.Context) error {
	caCertPath := c.String("ca-cert")
	caKeyPath := c.String("ca-key")
	outputDir := c.String("output-dir")
	clientName := c.String("name")
	organization := c.String("organization")
	keySize := c.Int("key-size")
	validityDays := c.Int("validity")
	force := c.Bool("force")

	// Load CA certificate and key
	caCert, caKey, err := loadCA(caCertPath, caKeyPath)
	if err != nil {
		return err
	}

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Check if files already exist
	certPath := filepath.Join(outputDir, fmt.Sprintf("%s.crt", clientName))
	keyPath := filepath.Join(outputDir, fmt.Sprintf("%s.key", clientName))

	if !force {
		if _, err := os.Stat(certPath); err == nil {
			return fmt.Errorf("certificate file already exists: %s (use --force to overwrite)", certPath)
		}
		if _, err := os.Stat(keyPath); err == nil {
			return fmt.Errorf("key file already exists: %s (use --force to overwrite)", keyPath)
		}
	}

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(validityDays) * 24 * time.Hour)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   clientName,
			Organization: []string{organization},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Create certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &privateKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Write certificate to file
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to open certificate file for writing: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("failed to write certificate to file: %w", err)
	}

	// Write private key to file
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open key file for writing: %w", err)
	}
	defer keyOut.Close()

	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("failed to write key to file: %w", err)
	}

	// Create a combined PEM file (cert + key) for convenience
	pfxPath := filepath.Join(outputDir, fmt.Sprintf("%s.pem", clientName))
	pfxOut, err := os.Create(pfxPath)
	if err != nil {
		return fmt.Errorf("failed to create combined PEM file: %w", err)
	}
	defer pfxOut.Close()

	// Write certificate
	if err := pem.Encode(pfxOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("failed to write certificate to combined PEM file: %w", err)
	}

	// Write private key
	if err := pem.Encode(pfxOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("failed to write key to combined PEM file: %w", err)
	}

	fmt.Printf("Client certificate created successfully:\n")
	fmt.Printf("  - Certificate: %s\n", certPath)
	fmt.Printf("  - Private key: %s\n", keyPath)
	fmt.Printf("  - Combined PEM: %s\n", pfxPath)
	fmt.Printf("  - Client Name: %s\n", clientName)
	fmt.Printf("  - Validity: %d days (until %s)\n", validityDays, notAfter.Format("2006-01-02"))

	return nil
}

// createSelfSignedCert creates a self-signed certificate
func createSelfSignedCert(c *cli.Context) error {
	outputDir := c.String("output-dir")
	commonName := c.String("common-name")
	dnsNames := c.StringSlice("dns")
	ipAddresses := c.StringSlice("ip")
	organization := c.String("organization")
	keySize := c.Int("key-size")
	validityDays := c.Int("validity")
	force := c.Bool("force")

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Check if files already exist
	certPath := filepath.Join(outputDir, "server.crt")
	keyPath := filepath.Join(outputDir, "server.key")

	if !force {
		if _, err := os.Stat(certPath); err == nil {
			return fmt.Errorf("certificate file already exists: %s (use --force to overwrite)", certPath)
		}
		if _, err := os.Stat(keyPath); err == nil {
			return fmt.Errorf("key file already exists: %s (use --force to overwrite)", keyPath)
		}
	}

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Parse IP addresses
	var ips []net.IP
	for _, ip := range ipAddresses {
		if ip != "" {
			ips = append(ips, net.ParseIP(ip))
		}
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(validityDays) * 24 * time.Hour)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{organization},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}

	// Create self-signed certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Write certificate to file
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to open certificate file for writing: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("failed to write certificate to file: %w", err)
	}

	// Write private key to file
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open key file for writing: %w", err)
	}
	defer keyOut.Close()

	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("failed to write key to file: %w", err)
	}

	fmt.Printf("Self-signed certificate created successfully:\n")
	fmt.Printf("  - Certificate: %s\n", certPath)
	fmt.Printf("  - Private key: %s\n", keyPath)
	fmt.Printf("  - Common Name: %s\n", commonName)
	fmt.Printf("  - DNS Names: %s\n", strings.Join(dnsNames, ", "))
	fmt.Printf("  - IP Addresses: %s\n", strings.Join(ipAddresses, ", "))
	fmt.Printf("  - Validity: %d days (until %s)\n", validityDays, notAfter.Format("2006-01-02"))

	return nil
}

// loadCA loads a CA certificate and private key from files
func loadCA(certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Read CA certificate
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate PEM")
	}

	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Read CA private key
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CA private key: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to parse CA private key PEM")
	}

	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA private key: %w", err)
	}

	return caCert, caKey, nil
}

// GenerateCertificateBundle generates a certificate bundle for the server
func GenerateCertificateBundle(cfg *config.Config) error {
	// Get TLS configuration
	if cfg.Listen == nil {
		return fmt.Errorf("listen configuration is missing")
	}

	tlsCert := cfg.Listen.GetTLSCert()
	tlsKey := cfg.Listen.GetTLSKey()

	// Check if TLS is configured
	if tlsCert == "" || tlsKey == "" {
		return fmt.Errorf("TLS certificate and key paths must be configured")
	}

	// Check if certificates already exist
	if _, err := os.Stat(tlsCert); err == nil {
		return fmt.Errorf("certificate already exists: %s", tlsCert)
	}
	if _, err := os.Stat(tlsKey); err == nil {
		return fmt.Errorf("key already exists: %s", tlsKey)
	}

	// Create directories
	certDir := filepath.Dir(tlsCert)
	keyDir := filepath.Dir(tlsKey)

	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("failed to create certificate directory: %w", err)
	}
	if err := os.MkdirAll(keyDir, 0755); err != nil {
		return fmt.Errorf("failed to create key directory: %w", err)
	}

	// Generate self-signed certificate
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // 1 year

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{common.AppName + " Auto-generated Certificate"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Add server hostname to certificate
	host := cfg.Listen.Host

	if host != "" && host != "0.0.0.0" && host != "127.0.0.1" {
		template.DNSNames = append(template.DNSNames, host)
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}

	// Create self-signed certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Write certificate to file
	certOut, err := os.Create(tlsCert)
	if err != nil {
		return fmt.Errorf("failed to open certificate file for writing: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("failed to write certificate to file: %w", err)
	}

	// Write private key to file
	keyOut, err := os.OpenFile(tlsKey, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open key file for writing: %w", err)
	}
	defer keyOut.Close()

	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("failed to write key to file: %w", err)
	}

	fmt.Printf("Auto-generated self-signed certificate:\n")
	fmt.Printf("  - Certificate: %s\n", tlsCert)
	fmt.Printf("  - Private key: %s\n", tlsKey)
	fmt.Printf("  - Validity: 365 days (until %s)\n", notAfter.Format("2006-01-02"))
	fmt.Printf("  - This certificate is for testing only and will not be trusted by browsers.\n")

	return nil
}
