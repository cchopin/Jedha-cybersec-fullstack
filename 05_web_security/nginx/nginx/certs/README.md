# SSL/TLS Certificates

This directory should contain SSL/TLS certificates for the Nginx server.

**IMPORTANT: Certificate files are excluded from git for security reasons.**

## Generating Self-Signed Certificates

### Option 1: Using mkcert (Recommended for development)

```bash
# Install mkcert
brew install mkcert  # macOS
# or
sudo apt install mkcert  # Linux

# Generate certificates
mkcert -install
mkcert -key-file key.pem -cert-file cert.pem localhost 127.0.0.1 ::1
```

### Option 2: Using OpenSSL

```bash
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout key.pem \
  -out cert.pem \
  -days 365 \
  -subj "/CN=localhost"
```

## Required Files

- `cert.pem` - SSL certificate
- `key.pem` - Private key

## Production Use

For production environments, use certificates from a trusted Certificate Authority (CA) like Let's Encrypt.
