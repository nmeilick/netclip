# netclip

[![Build Status](https://img.shields.io/github/actions/workflow/status/nmeilick/netclip/release.yml?branch=main)](https://github.com/nmeilick/netclip/actions/workflows/release.yml)
[![License](https://img.shields.io/github/license/nmeilick/netclip)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/nmeilick/netclip)](https://goreportcard.com/report/github.com/nmeilick/netclip)

**netclip** is a secure and convenient network clipboard for transferring files and directories between machines. It
acts like a temporary, encrypted storage accessible via simple command-line tools.

## Features

*   **Simple CLI:** Easy-to-use `ncopy` and `npaste` commands (symlinks to the main `netclip` binary).
*   **Secure:** End-to-end encryption using AGE (passphrase-based).
*   **Flexible:** Transfer single files, multiple files, directories, or data from stdin.
*   **Efficient:** Uses streaming and compression (LZ4 default, Zstd, Gzip optional) for fast transfers.
*   **Metadata Preservation:** Preserves file permissions, timestamps, and optionally extended attributes (xattrs) and ACLs across platforms (where supported).
*   **Self-Hosted Server:** Run your own `nserve` instance for complete control.
*   **Configurable:** Fine-tune server and client behavior via HCL configuration files.
*   **Temporary Storage:** Clips expire automatically (configurable TTL).
*   **Update Mechanism:** Update existing clips using a generated token.
*   **Cross-Platform:** Binaries available for Linux and Windows.

## Installation

### Pre-compiled Binaries

Download the latest pre-compiled binaries for your platform from the [Releases page](https://github.com/nmeilick/netclip/releases).

Extract the archive and place the `netclip` binary in a directory included in your system's `PATH`.

### Setup Symlinks (Optional but Recommended)

For convenience, you can create symbolic links named `ncopy`, `npaste`, and `nserve` pointing to the main `netclip` binary. This allows you to use the intuitive command names directly.

Run the following command from the directory containing the `netclip` binary:

```bash
./netclip setup links
```

This will create the necessary symlinks in the same directory.

## Usage

`netclip` operates through subcommands or symlinks (`ncopy`, `npaste`, `nserve`).

### Copying Data (`ncopy`)

Use `ncopy` to upload files or directories to the server.

```bash
# Copy a single file
ncopy file.txt

# Copy multiple files
ncopy file1.txt image.jpg

# Copy a directory
ncopy my_directory/

# Copy data from stdin
cat data.log | ncopy

# Encrypt with a specific password
ncopy -p mysecretpassword important_docs/

# Encrypt with a randomly generated password
ncopy -e sensitive_data.zip

# Set an expiration time (e.g., 1 hour)
ncopy -x 1h large_file.mkv

# Specify a custom ID
ncopy -i my-custom-id file.txt

# Update an existing clip (requires the update token)
ncopy -u <update_token> updated_file.txt
```

`ncopy` will output the clip ID (and password/update token if applicable) and optionally a QR code for easy pasting on other devices.

### Pasting Data (`npaste`)

Use `npaste` to download files or directories from the server.

```bash
# Paste a clip into the current directory
npaste <clip_id> .

# Paste a clip into a specific directory
npaste <clip_id> /path/to/destination/

# Paste an encrypted clip (will prompt for password if not provided)
npaste <clip_id>:<password> .

# Paste raw data to stdout
npaste <clip_id>

# Force overwrite existing files
npaste -f <clip_id> .
```

### Running the Server (`nserve`)

Use `nserve` to start the netclip server.

```bash
# Start the server using the default configuration file
nserve start

# Start the server with a specific configuration file
nserve start --config /path/to/netclip.hcl

# Start in the foreground
nserve start -f

# Auto-generate TLS certificate if needed (requires TLS config)
nserve start -g
```

The server requires a configuration file. See the [Configuration](#configuration) section below.

### Other Commands

*   `netclip setup sample-config`: Print a sample configuration file to stdout.
*   `netclip setup embedded-config`: Print the embedded default configuration (if available).
*   `ncopy -l`: List cached clip IDs, update tokens, and passwords.
*   `ncopy --clean`: Clear the local clip cache.
*   `nserve certs ...`: Manage TLS certificates (create CA, server/client certs).

## Configuration

`netclip` uses HCL configuration files. By default, it looks for configuration in standard locations (e.g., `~/.config/netclip.hcl`, `/etc/netclip/config.hcl`, or next to the executable). You can specify a config file using the `--config` flag.

A sample configuration file can be generated using:

```bash
netclip setup sample-config > netclip.hcl
```

The configuration file has two main blocks: `server` and `client`.

### Server Configuration (`server` block)

*   `listen`: Network interface, port, timeouts, and TLS settings.
*   `storage_path`: Directory to store clip data. **Required**.
*   `default_ttl`: Default expiration time for clips (e.g., "24h", "7d").
*   `cleanup_every`: How often to check for and delete expired clips.
*   `acme`: Configure automatic TLS certificates using Let's Encrypt (requires public server).
*   `log`: Configure logging (directory, rotation, etc.).
*   `api_prefix`: Optional URL prefix for API endpoints.
*   `disable_swagger`: Disable the Swagger UI endpoint.
*   `require_api_key`: Require API keys for all requests.
*   `security`: Configure security headers (HSTS, Cache-Control).
*   `limits`: Default limits for upload size and maximum age.
*   `api_key`: Define API keys for authentication/authorization and per-key limits/prefixes.
*   `requestqueue`: Configure global and per-IP request rate limiting.

See `examples/netclip.hcl` or the output of `netclip setup sample-config` for detailed options.

### Client Configuration (`client` block)

*   `server_url`: URL of the `nserve` instance.
*   `api_key`: Default API key to use.
*   `password`: Default password for encryption (used with `-e` if no other password specified).
*   `password_length`, `id_length`, `update_token_length`: Default lengths for generated values.
*   `tls_skip_verify`: Disable TLS certificate verification (INSECURE, use for testing only).
*   `tls_cert`, `tls_key`, `tls_ca`: Paths for client-side TLS certificates (mTLS).
*   `proxy_url`: HTTP/S proxy server URL.
*   `connection_timeout`, `metadata_timeout`: Network timeouts.
*   `disable_qr_code`: Disable QR code output by default.

## Building from Source

**Prerequisites:**

*   Go 1.23 or later
*   Make (optional, for using the Makefile)
*   Swag CLI (`go install github.com/swaggo/swag/cmd/swag@latest`) (for updating API docs)

**Steps:**

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/nmeilick/netclip.git
    cd netclip
    ```

2.  **Build using Go:**
    ```bash
    go build ./cmd/netclip
    # The binary will be created as 'netclip' in the current directory
    ```

3.  **Build using Make (includes version info, swagger docs):**
    ```bash
    make build
    # Binaries and symlinks will be in cmd/netclip/bin/
    ```

4.  **Install dependencies (needed for Make):**
    ```bash
    make deps
    ```

5.  **Generate Swagger docs (if modifying API):**
    ```bash
    make swagger
    ```

6.  **Build distribution binaries:**
    ```bash
    make dist
    ```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
