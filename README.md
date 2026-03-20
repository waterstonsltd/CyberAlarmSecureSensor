# CyberAlarm Secure Sensor

The **CyberAlarm Secure Sensor** is the syslog relay component of the [Police CyberAlarm](https://www.cyberalarm.police.uk) (PCA) platform. It securely collects, encrypts, and forwards syslog data from network devices to the central PCA platform for analysis and threat detection.

This repository contains the source code for the sensor component only. The central processing platform, analytics engines, and other PCA components are not included.

## About Police CyberAlarm

Police CyberAlarm is a cybersecurity monitoring service provided to UK police forces and public sector organisations, helping detect and respond to cyber threats in real time. The platform is developed by [Waterstons](https://www.waterstons.com) in partnership with the National Police Chiefs' Council (NPCC) and aligns with [NCSC guidance](https://www.ncsc.gov.uk/) on cybersecurity monitoring.

## Features

- **Syslog collection** receives syslog data over UDP and TCP (port 514)
- **End-to-end encryption** RSA-4096 signatures with PSS padding and AES-256-GCM payload encryption
- **Secure transmission** SFTP-based upload to Azure infrastructure
- **Containerised deployment** minimal, production-ready Docker images

## Requirements

- Docker 20.10 or later
- A Linux server with a static IP address
- Network connectivity to syslog sources
- A registration token from the [CyberAlarm portal](https://member.cyberalarm.police.uk)

---

## Image Tags

Container images are published under two tags with different stability guarantees:

| Tag | Description |
|-----|-------------|
| `latest` | Builds we believe are ready, but have not yet been formally promoted. Suitable for evaluation and testing. **Auto-update will not move you to a new `latest` build.** |
| `stable` | Builds that have been validated over time and formally promoted. Recommended for all production deployments. |

When a `latest` build has been running without issue for a suitable period, we promote it to `stable` by applying that tag. If you are deploying in a production or operational environment, pin to `stable` rather than `latest`.

The one-line installer and provided Docker Compose file both default to `stable`.

---

## Installation

### Prerequisites: Install Cosign

The installer verifies container image signatures before deployment. [Cosign](https://docs.sigstore.dev/) must be installed first:

```bash
curl -LO https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
chmod +x cosign-linux-amd64
sudo mv cosign-linux-amd64 /usr/local/bin/cosign
```

Verify it installed correctly:

```bash
cosign version
```

### Recommended: One-Line Installer

The installer script handles Docker setup, container deployment, and configuration in a single step.

> **Security notice:** always verify the installer's integrity before execution. The SHA256 hash of the current installer is:
> ```
> 87d1adfebb15903a14d613b02ad7a8fb324fb45f08d00330550493e2b715c423
> ```
> Cross-reference this against the hash shown on the [CyberAlarm portal](https://member.cyberalarm.police.uk) before running.

```bash
curl -fsSL https://raw.githubusercontent.com/waterstonsltd/CyberAlarmSecureSensor/refs/heads/main/installer/pca-install.sh -o pca-install.sh \
  && echo "87d1adfebb15903a14d613b02ad7a8fb324fb45f08d00330550493e2b715c423  pca-install.sh" | sha256sum --check \
  && sudo bash pca-install.sh <TOKEN>
```

To enable automatic updates (recommended), append `auto-update`:

```bash
curl -fsSL https://raw.githubusercontent.com/waterstonsltd/CyberAlarmSecureSensor/refs/heads/main/installer/pca-install.sh -o pca-install.sh \
  && echo "87d1adfebb15903a14d613b02ad7a8fb324fb45f08d00330550493e2b715c423  pca-install.sh" | sha256sum --check \
  && sudo bash pca-install.sh <TOKEN> auto-update
```

> The installer defaults to the `stable` tag. Automatic updates will only move you between promoted `stable` builds.

### Docker Compose

If you prefer to manage the deployment yourself, you can use the provided Docker Compose file.

The `docker-compose.yaml` has a published SHA256 hash so you can verify it has not been tampered with:

```
888ec31188e97f2628d787a42d0171bba50152cd065ae0fd37764197c93bdf01
```

```bash
# Create the install directory and set ownership for the container user
mkdir -p /opt/cyberalarm/data
chown 1654:1654 /opt/cyberalarm/data
cd /opt/cyberalarm

# Download and verify the compose file
curl -fsSL https://raw.githubusercontent.com/waterstonsltd/CyberAlarmSecureSensor/refs/heads/main/installer/docker-compose.yaml -o docker-compose.yaml
echo "888ec31188e97f2628d787a42d0171bba50152cd065ae0fd37764197c93bdf01  docker-compose.yaml" | sha256sum --check

# Create the environment file with your registration token
echo "REGISTRATION_TOKEN=<TOKEN>" > .env
chmod 600 .env

# Deploy
docker compose up -d
```

If the hash check fails, do not proceed - download a fresh command from the [CyberAlarm portal](https://member.cyberalarm.police.uk).

> **Keeping up to date:** if you are not using the auto-update flag, you are responsible for keeping the container current. Run `docker compose pull && docker compose up -d` to update. The provided Compose file defaults to the `stable` tag.

### Docker Run

For standalone Docker deployments without Compose:

```bash
# Create and permission the data directory
mkdir -p ./data
chown 1654:1654 ./data

# Run the container
docker run -d \
  --name syslog-relay \
  --restart unless-stopped \
  -v ./data:/var/lib/syslog-relay:rw \
  -p 514:514/udp \
  -p 514:514/tcp \
  -e REGISTRATION_TOKEN=<TOKEN> \
  ghcr.io/waterstonsltd/cyberalarm-securesensor:stable
```

> Replace `stable` with `latest` if you want to track builds ahead of formal promotion, but note these have not yet completed our validation period.

---

## Configuration

All settings can be supplied as Docker environment variables. In .NET, environment variables override values in `appsettings.json`, and nested keys use `__` as the separator (e.g. `Logging__LogLevel__Default`).

The provided Docker Compose file already passes the most common variables via a `.env` file. Any additional variable below can be added to that file or passed directly in the `environment:` block.

### Required

| Variable | Description |
|----------|-------------|
| `REGISTRATION_TOKEN` | Your registration token from the [CyberAlarm portal](https://member.cyberalarm.police.uk). The sensor will not start without this. |

### Commonly Changed

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `Information` | Controls log verbosity. Accepted values: `Trace`, `Debug`, `Information`, `Warning`, `Error`, `Critical`, `None`. Use `Debug` for troubleshooting, `Warning` to reduce noise in production. |
| `AdditionalLocalSubnet` | *(empty)* | A CIDR subnet to treat as local, in addition to the standard RFC 1918 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`). Events where both source and destination IPs fall within a local subnet are not uploaded. Example: `AdditionalLocalSubnet=192.0.2.0/24`. |
| `MaximumTcpClients` | `3` | Maximum number of simultaneous TCP connections accepted on port 514. Additional connections are immediately disconnected. Increase if you have many syslog sources connecting over TCP. |
| `UploadRawLogs` | `false` | When `true`, raw grouped log files are included in uploads alongside the encrypted event bundles. |
| `FileWatcherDropPath` | *(empty)* | Path to a directory the sensor watches for syslog files to ingest (drop folder pattern). Leave empty to disable file watching entirely. When set, the directory must exist before the sensor starts. Example: `FileWatcherDropPath=/mnt/drop`. |

### Advanced Tuning

These settings have sensible defaults and do not normally need to be changed.

| Variable | Default | Description |
|----------|---------|-------------|
| `UploadIntervalInMinutes` | `60` | How often the upload cycle runs — file selection, grouping, bundling, and upload to the central platform. |
| `ChannelCapacity` | `10000` | Size of the bounded in-memory channel buffers between pipeline stages. If a downstream stage falls behind, upstream stages will apply back-pressure. Reduce on memory-constrained hosts. |
| `PersistenceBufferSize` | `1000` | Number of parsed events held in memory before being flushed to disk. |
| `PersistenceBufferIntervalInSeconds` | `60` | Maximum time (seconds) between disk flushes. Events are flushed when either this interval or `PersistenceBufferSize` is reached, whichever comes first. |
| `PatternMatchingScanLength` | `300` | Number of characters from the start of each syslog message that are scanned when evaluating `ContainsAll`/`ContainsAny` pattern rules. Limits the search window to improve throughput. |
| `PatternMatchingCacheDurationInSeconds` | `3600` | How long the compiled pattern matcher is cached before being rebuilt from the latest status response. |
| `FileWatcherIntervalInSeconds` | `3600` | How often the file watcher scans `FileWatcherDropPath` for new files. |
| `FileWatcherMaximumRetryCount` | `5` | Number of times a file in the drop folder will be retried before being permanently skipped. |
| `RawGroupedLogsMaxFileSizeBytes` | `5368709120` | Maximum size in bytes of a single grouped raw log file before it is rolled to a new file. Default is 5 GB. |
| `EnableRequestLogging` | `true` | When `true`, logs outgoing HTTP request payloads at Debug level. Set to `false` to reduce log verbosity. |
| `StatusEndpoint` | *(set by CI)* | URL of the CyberAlarm status API. This is pre-configured for your environment and should not be changed unless instructed by the CyberAlarm team. |

### Example `.env` file

```env
# Required
REGISTRATION_TOKEN=your-token-here

# Optional overrides
LOG_LEVEL=Information
AdditionalLocalSubnet=192.0.2.0/24
MaximumTcpClients=5
UploadIntervalInMinutes=30
FileWatcherDropPath=/mnt/drop
```

---

## Automatic Updates

When you install with the `auto-update` flag, the installer writes an update script at `/opt/cyberalarm/scripts/update.sh` and registers it as a cron job that runs once per hour.

The update script is generated inline by the installer — it is a simple wrapper around `docker compose pull && docker compose up -d`. Docker Compose will only recreate containers whose image digest has actually changed, so the service is not restarted unnecessarily.

All activity is logged to `/var/log/cyberalarm-update.log`. The log is cleared at the start of each run and contains only the output from the most recent execution.

### What the update script does

Each time it runs, the script:

1. Pulls the latest images for all services defined in the Compose file
2. Runs `docker compose up -d` — Docker Compose recreates only containers whose image has changed

### Running the update manually

```bash
sudo /opt/cyberalarm/scripts/update.sh
```

Or run the equivalent commands directly:

```bash
cd /opt/cyberalarm
docker compose pull
docker compose up -d
```

### Disabling automatic updates

To remove the cron job:

```bash
crontab -l | grep -v '/opt/cyberalarm/scripts/update.sh' | crontab -
```

You will then be responsible for keeping the container current by running `docker compose pull && docker compose up -d` from `/opt/cyberalarm` when you want to update.

---

## Security

### Coordinated Vulnerability Disclosure

We operate a Coordinated Vulnerability Disclosure (CVD) process in accordance with [NCSC guidance](https://www.ncsc.gov.uk/information/coordinated-vulnerability-disclosure-definitions-and-processes). If you discover a security vulnerability, **do not** open a public GitHub issue - please see our [security policy](https://github.com/waterstonsltd/CyberAlarmSecureSensor/tree/main?tab=security-ov-file) for reporting instructions and our PGP key.

### Supply Chain Security

Every release includes the following supply chain controls:

| Control | Detail |
|---------|--------|
| **Image signing** | All container images are signed using [Sigstore Cosign](https://docs.sigstore.dev/) keyless signing |
| **SBOM** | A CycloneDX Software Bill of Materials is generated and attested to each image |
| **Static analysis** | All releases undergo automated security scanning before publication |
| **Installer integrity** | SHA256 hashes for the installer and Docker Compose file are published and embedded at release time by the CI pipeline |

Both `latest` and `stable` tagged images are signed and attested. You can verify either tag using the commands below.

### Verifying Image Signatures

All published images are cryptographically signed. This provides proof that images were built by our official GitHub Actions pipeline and have not been tampered with.

**Verify an image:**

```bash
cosign verify \
  --certificate-identity-regexp="https://github.com/waterstonsltd/CyberAlarmSecureSensor/.*" \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  ghcr.io/waterstonsltd/cyberalarm-securesensor:stable
```

This confirms the image was built from the official Waterstons repository, has not been modified since signing, and that the signer identity is cryptographically proven via Sigstore's transparency log.

### Verifying the SBOM

The SBOM lists all components, dependencies, and versions included in the container image.

**Verify the SBOM attestation:**

```bash
cosign verify-attestation \
  --certificate-identity-regexp="https://github.com/waterstonsltd/CyberAlarmSecureSensor/.*" \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --type cyclonedx \
  ghcr.io/waterstonsltd/cyberalarm-securesensor:stable
```

**Download the SBOM for inspection:**

```bash
cosign download attestation \
  --predicate-type=cyclonedx \
  ghcr.io/waterstonsltd/cyberalarm-securesensor:stable | \
  jq -r '.payload' | base64 -d | jq '.predicate' > sbom.json

cat sbom.json | jq .
```

The SBOM is also attached as a downloadable asset on each [GitHub Release](https://github.com/waterstonsltd/CyberAlarmSecureSensor/releases).

---

## Compliance

The CyberAlarm Secure Sensor is designed for deployment in environments requiring:

- **NCSC compliance** - aligned with NCSC cybersecurity guidance
- **HMG security standards** - appropriate for UK government and law enforcement use
- **RMADS** - Risk Management and Accreditation documentation is available to authorised organisations upon request

---

## License

This project is released under the **Business Source License 1.1**.

- **Source available** - you can view, inspect, and audit the code
- **Permitted use** - non-commercial deployment within UK law enforcement and policing organisations for cybersecurity monitoring
- **Restrictions** - commercial use, redistribution, and SaaS offerings require a commercial licence
- **Change date** - converts to Apache License 2.0 on 2030-02-17

See [LICENSE](https://github.com/waterstonsltd/CyberAlarmSecureSensor/tree/main?tab=License-1-ov-file) for full terms.

---

## Contributing

This repository is read-only for external users. We do not accept pull requests or external contributions at this time.

If you are a UK police force or public sector organisation interested in deploying CyberAlarm, please contact **enquiries@cyberalarm.police.uk**.

## Support

- **Deployment and operational queries:** [cyberalarm.police.uk/contact](https://www.cyberalarm.police.uk/contact)
- **Security vulnerabilities:** see [SECURITY.md](https://github.com/waterstonsltd/CyberAlarmSecureSensor/tree/main?tab=security-ov-file)

## Governance

CyberAlarm is developed by **Waterstons Ltd** in partnership with the **National Police Chiefs' Council (NPCC)**. Technical governance and risk assessment documentation is available to authorised organisations on request.

## Acknowledgements

CyberAlarm is made possible through collaboration between [Waterstons Ltd](https://www.waterstons.com), the [National Police Chiefs' Council](https://www.npcc.police.uk/), UK police forces, and the [National Cyber Security Centre](https://www.ncsc.gov.uk/).
