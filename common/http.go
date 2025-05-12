package common

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/nmeilick/netclip/client/config"
)

// CreateHTTPClient creates an HTTP client with the appropriate configuration
func CreateHTTPClient(cfg *config.Config) *http.Client {
	// Create transport with proxy support
	transport := &http.Transport{
		// Use default proxy from environment if none specified
		Proxy: http.ProxyFromEnvironment,
		// Set connect timeout
		DialContext: (&net.Dialer{
			Timeout: 20 * time.Second,
		}).DialContext,
	}

	// Configure proxy if specified in config
	if cfg != nil && cfg.ProxyURL != "" {
		proxyURL, err := url.Parse(cfg.ProxyURL)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	// Configure TLS if needed
	if cfg != nil && (cfg.TLSCert != "" || cfg.TLSKey != "" || cfg.TLSCA != "" || cfg.TLSSkipVerify) {
		tlsConfig := &tls.Config{}

		// Load CA cert if provided
		if cfg.TLSCA != "" {
			caCert, err := os.ReadFile(cfg.TLSCA)
			if err == nil {
				caCertPool := x509.NewCertPool()
				caCertPool.AppendCertsFromPEM(caCert)
				tlsConfig.RootCAs = caCertPool
			}
		}

		// Load client cert if provided
		if cfg.TLSCert != "" && cfg.TLSKey != "" {
			cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
			if err == nil {
				tlsConfig.Certificates = []tls.Certificate{cert}
			}
		}

		// Skip verification if requested
		tlsConfig.InsecureSkipVerify = cfg.TLSSkipVerify

		transport.TLSClientConfig = tlsConfig
	}

	// Create client with transport and timeout
	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.GetConnectionTimeout(),
	}

	return client
}

// SetUserAgent sets the User-Agent header on the request
func SetUserAgent(req *http.Request) {
	if req != nil {
		req.Header.Set("User-Agent", fmt.Sprintf("%s/%s", AppName, Version))
	}
}
