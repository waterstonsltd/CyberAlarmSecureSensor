# TLS Syslog (RFC 5425)

The relay supports encrypted syslog over TLS on port **6514** (RFC 5425). TLS is **opt-in** — the relay starts normally with TLS disabled and you enable it by providing certificates.

Two modes are available:

| Mode | What it does |
|---|---|
| **Server-only TLS** | Encrypts the connection. The firewall does not need to present a certificate. |
| **Mutual TLS (mTLS)** | Encrypts the connection and requires the firewall to authenticate with a client certificate signed by an operator-supplied CA. |

---

## Certificate requirements

You must supply your own certificates. The relay does not generate them.

| File | Format | Purpose |
|---|---|---|
| `server.pfx` | PKCS#12 (PFX) | Server certificate and private key. Presented to connecting firewalls. |
| `ca.crt` | PEM or DER | CA certificate used to validate client certificates (mutual TLS only). |

### Generating certificates with OpenSSL

These commands produce a self-signed CA, a server certificate, and an optional client certificate. Use them as a starting point for testing — for production use your organisation's PKI.

**1. Generate the CA key and certificate**

```bash
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
  -subj "/CN=Syslog Relay CA" -out ca.crt
```

**2. Generate the server key and certificate**

```bash
openssl genrsa -out server.key 2048
openssl req -new -key server.key -subj "/CN=syslog-relay" -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 825 -sha256 \
  -extfile <(printf "subjectAltName=DNS:syslog-relay,DNS:localhost") \
  -out server.crt
openssl pkcs12 -export -out server.pfx -inkey server.key -in server.crt \
  -certfile ca.crt -passout pass:changeme
```

**3. Generate a client certificate (mutual TLS only)**

```bash
openssl genrsa -out client.key 2048
openssl req -new -key client.key -subj "/CN=firewall-01" -out client.csr
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 825 -sha256 \
  -extfile <(printf "extendedKeyUsage=clientAuth") \
  -out client.crt
openssl pkcs12 -export -out client.pfx -inkey client.key -in client.crt \
  -passout pass:changeme
```

---

## Docker Compose configuration

Place your certificate files in a directory alongside the Compose file, then make the following additions manually to `docker-compose.yaml`.

```bash
/opt/cyberalarm/
  docker-compose.yaml
  .env
  certs/
    server.pfx
    ca.crt          # mutual TLS only
```

**1. Add the certs volume mount** under `volumes:`:

```yaml
    volumes:
      - ./data:/var/lib/syslog-relay:rw
      - ./certs:/certs:ro       # add this line
```

**2. Expose port 6514** under `ports:`:

```yaml
    ports:
      - 514:514/udp
      - 514:514/tcp
      - 6514:6514/tcp           # add this line
```

**3. Add the TLS environment variables** under `environment:`:

```yaml
    environment:
      - REGISTRATION_TOKEN=${REGISTRATION_TOKEN}
      # ... existing variables ...
      - TlsEnabled=true
      - TlsCertificatePath=/certs/server.pfx
      - TlsCertificatePassword=changeme
      - TlsRequireClientCertificate=false   # set true for mutual TLS
      - TlsClientCaCertificatePath=/certs/ca.crt
      - TlsPort=6514
```

After editing the file, apply the changes:

```bash
docker compose up -d
```

### Environment variable reference

| Variable | Default | Description |
|---|---|---|
| `TlsEnabled` | `false` | Set to `true` to enable TLS listening. |
| `TlsCertificatePath` | `/certs/server.pfx` | Path to the server PKCS#12 file inside the container. |
| `TlsCertificatePassword` | *(empty)* | Password for the PKCS#12 file. Leave empty if the file has no password. |
| `TlsRequireClientCertificate` | `false` | Set to `true` to require mutual TLS. |
| `TlsClientCaCertificatePath` | `/certs/ca.crt` | Path to the CA certificate used to validate client certs (mutual TLS only). |
| `TlsPort` | `6514` | TCP port to listen on. |

---

## Health check

When `TlsEnabled=true`, the TLS listener registers with the health check system. If the listener fails to start (for example, because the certificate file is missing or the password is wrong), the container reports **unhealthy** and the application stops. Fix the configuration and restart the container.

When `TlsEnabled=false` (the default), the TLS listener is not registered in the health check and does not affect overall health.

---

## Smoke test with openssl s_client

Verify the relay is accepting TLS connections:

```bash
# Server-only TLS
openssl s_client -connect <host>:6514 -CAfile ca.crt

# Mutual TLS — supply the client certificate
openssl s_client -connect <host>:6514 -CAfile ca.crt \
  -cert client.crt -key client.key
```

A successful handshake shows `Verify return code: 0 (ok)`. You can then type a syslog message and press Enter to confirm ingestion.

---

## Firewall configuration notes

- The relay listens on TCP port **6514** by default.
- Open port 6514/TCP inbound on the host firewall.
- Configure your network device to send encrypted syslog to the relay's IP address on port 6514.
- For mutual TLS, import the `client.pfx` (or equivalent) into the firewall and configure it to use that certificate for syslog.

Consult your firewall vendor's documentation for device-specific TLS syslog configuration steps.
