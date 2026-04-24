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

| File | Required for | Format | Purpose |
|---|---|---|---|
| `server.pfx` | Both modes | PKCS#12 (PFX) | Server certificate and private key, presented to connecting firewalls. |
| `ca.crt` | Mutual TLS only | PEM or DER | CA certificate used to validate client certificates. Not needed for server-only TLS. |

For server-only TLS, use any certificate you have available — from your organisation's PKI, a public CA, or a self-signed certificate. The relay only needs the PKCS#12 file at runtime.

The server certificate must include:

- A private key
- The **Server Authentication** EKU (`1.3.6.1.5.5.7.3.1`)

**[Let's Encrypt](https://letsencrypt.org/)** (via [Certbot](https://certbot.eff.org/)) is a good free option for the server certificate if the relay host has a public hostname and can complete an ACME challenge. Note that Let's Encrypt issues server certificates only — it cannot issue client certificates for mutual TLS.

Certbot stores certificates as PEM files (`privkey.pem`, `cert.pem`, `chain.pem`, `fullchain.pem`). The relay does not read those files directly — it expects a PKCS#12 (`.pfx`) file, so you must convert the Certbot output with:

```bash
openssl pkcs12 -export -out server.pfx \
  -inkey /etc/letsencrypt/live/<domain>/privkey.pem \
  -in /etc/letsencrypt/live/<domain>/fullchain.pem \
  -passout pass:changeme
```

The container runs as a non-root user, so `server.pfx` must also be readable by that user through the bind mount. After creating or renewing the file, make sure the mounted certificate directory and files have suitable ownership and permissions. For example:

```bash
sudo chown -R 1654:1654 /opt/cyberalarm/certs
sudo chmod 750 /opt/cyberalarm/certs
sudo chmod 640 /opt/cyberalarm/certs/server.pfx
sudo chmod 640 /opt/cyberalarm/certs/ca.crt   # mutual TLS only
```

The installer already uses `1654:1654` for the relay's writable data directory, and the same ownership should be used for the mounted certificate files so the container can read them while write access remains limited to the host.

This matters operationally because Let's Encrypt certificates are short-lived and renewed regularly. Certbot renewal updates the PEM files, but it does **not** automatically rebuild your `server.pfx`, and the relay only loads the certificate when it starts.

After each renewal you must:

1. Rebuild `server.pfx` from the renewed PEM files.
2. Restart or recreate the relay container so it loads the new certificate.

If you use Certbot in production, automate both steps with a deploy hook. For example:

```bash
#!/bin/sh
set -eu

openssl pkcs12 -export -out /opt/cyberalarm/certs/server.pfx \
  -inkey /etc/letsencrypt/live/<domain>/privkey.pem \
  -in /etc/letsencrypt/live/<domain>/fullchain.pem \
  -passout pass:changeme

chown 1654:1654 /opt/cyberalarm/certs/server.pfx
chmod 640 /opt/cyberalarm/certs/server.pfx

cd /opt/cyberalarm
docker compose up -d
```

Register the script as a Certbot deploy hook so it runs after each successful renewal.

**For mutual TLS**, Let's Encrypt is not suitable — you need your own CA to issue client certificates to your firewalls. Since you must run a CA anyway, it is simplest to use that same CA to sign the server certificate too, rather than mixing a public CA for the server with a private CA for clients.

### Generating test certificates with OpenSSL

These commands are a starting point for testing. For production, use your organisation's PKI or a trusted CA.

**Server-only TLS** — a self-signed server certificate is sufficient.

> **Certificate validity:** The server certificate is issued for **10 years** (`-days 3650`). Firewalls typically cache the certificate and use it for years without renewal, so a long-lived cert avoids unexpected connectivity loss. If you use Let's Encrypt instead (see below), its certs expire after 90 days and require automated renewal.

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout server.key \
  -subj "/CN=syslog-relay" -days 3650 \
  -addext "subjectAltName=DNS:syslog-relay,DNS:localhost" \
  -addext "extendedKeyUsage=serverAuth" \
  -out server.crt
openssl pkcs12 -export -out server.pfx -inkey server.key -in server.crt \
  -passout pass:changeme
```

**Mutual TLS** — you need a CA to sign both the server and client certificates:

```bash
# 1. Generate the CA
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
  -subj "/CN=Syslog Relay CA" -out ca.crt

# 2. Generate the server certificate signed by the CA
openssl genrsa -out server.key 2048
openssl req -new -key server.key -subj "/CN=syslog-relay" -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 3650 -sha256 \
  -extfile <(printf "subjectAltName=DNS:syslog-relay,DNS:localhost\nextendedKeyUsage=serverAuth") \
  -out server.crt
openssl pkcs12 -export -out server.pfx -inkey server.key -in server.crt \
  -certfile ca.crt -passout pass:changeme

# 3. Generate the client certificate signed by the same CA
openssl genrsa -out client.key 2048
openssl req -new -key client.key -subj "/CN=firewall-01" -out client.csr
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 3650 -sha256 \
  -extfile <(printf "extendedKeyUsage=clientAuth") \
  -out client.crt
openssl pkcs12 -export -out client.pfx -inkey client.key -in client.crt \
  -passout pass:changeme
```

---

## Docker Compose configuration

Place your certificate files in a directory alongside the Compose file, then make the following additions manually to `docker-compose.yaml`.

Before starting the container, ensure the mounted `certs/` directory and the files inside it are readable by the non-root user that runs inside the container. Use ownership `1654:1654` to match the relay container's runtime user.

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

If you are enabling TLS, we recommend removing port 514 unless you have devices that cannot use TLS. Leaving port 514 open allows unencrypted syslog from any source, which undermines the security benefit of TLS for the devices that do support it. The relay also disables the plaintext listeners by default when `TlsEnabled=true`, unless you set `AllowPlaintextListenersWhenTlsEnabled=true`.

**3. Add the TLS environment variables** under `environment:` — use the block for your chosen mode below.

After editing the file, apply the changes:

```bash
docker compose up -d
```

---

## Server-only TLS

The firewall connects and the connection is encrypted. The firewall does not need a client certificate.

**Certs directory:**
```
certs/
  server.pfx
```

**Environment variables:**
```yaml
    environment:
      - TlsEnabled=true
      - TlsCertificatePath=/certs/server.pfx
      - TlsCertificatePassword=changeme
```

`TlsRequireClientCertificate` defaults to `false` and does not need to be set.

`TlsPort` defaults to `6514` and usually does not need to be set. If you want a different external port, prefer changing the Docker port mapping rather than the application setting.

When `TlsEnabled=true`, the relay disables the plaintext UDP/TCP listeners on port 514 by default. This is the recommended setting.

If you need to keep port 514 enabled for legacy devices while also enabling TLS, set:

```yaml
  - AllowPlaintextListenersWhenTlsEnabled=true
```

---

## Mutual TLS (mTLS)

The connection is encrypted **and** the firewall must present a client certificate signed by your CA. Connections without a valid client certificate are rejected.

**Certs directory:**
```
certs/
  server.pfx
  ca.crt
```

**Environment variables:**
```yaml
    environment:
      - TlsEnabled=true
      - TlsCertificatePath=/certs/server.pfx
      - TlsCertificatePassword=changeme
      - TlsRequireClientCertificate=true
      - TlsClientCaCertificatePath=/certs/ca.crt
```

You must also import the client certificate (`client.pfx` from the generation steps above) into the firewall and configure it to use that certificate when sending syslog. Consult your firewall vendor's documentation for device-specific steps.

As with server-only TLS, plaintext UDP/TCP listeners on port 514 are disabled by default when TLS is enabled. Set `AllowPlaintextListenersWhenTlsEnabled=true` only if you need to support a mix of TLS and non-TLS devices.

`TlsPort` still defaults to `6514` here and usually does not need to be set. If you need a different external port, prefer changing the Docker port mapping.

---

### Environment variable reference

| Variable | Default | Description |
|---|---|---|
| `TlsEnabled` | `false` | Set to `true` to enable TLS listening. |
| `AllowPlaintextListenersWhenTlsEnabled` | `false` | When `TlsEnabled=true`, keeps the UDP/TCP listeners on port 514 enabled. |
| `TlsCertificatePath` | `/certs/server.pfx` | Path to the server PKCS#12 file inside the container. |
| `TlsCertificatePassword` | *(empty)* | Password for the PKCS#12 file. Leave empty if the file has no password. |
| `TlsRequireClientCertificate` | `false` | Set to `true` to require mutual TLS. |
| `TlsClientCaCertificatePath` | `/certs/ca.crt` | Path to the CA certificate used to validate client certs (mutual TLS only). |
| `TlsPort` | `6514` | TCP port to listen on inside the container. This is an uncommon internal override; most deployments should leave it unchanged and, if needed, map a different external port in Docker. |

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
