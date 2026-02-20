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
> fc14139e09d3783d6c6fcd86d9424c1254142484a8aa7776f0213734fb028626
> ```
> Cross-reference this against the hash shown on the [CyberAlarm portal](https://member.cyberalarm.police.uk) before running.

```bash
curl -fsSL https://raw.githubusercontent.com/waterstonsltd/CyberAlarmSecureSensor/refs/heads/main/installer/pca-install.sh -o pca-install.sh \
  && echo "fc14139e09d3783d6c6fcd86d9424c1254142484a8aa7776f0213734fb028626  pca-install.sh" | sha256sum --check \
  && sudo bash pca-install.sh <TOKEN>
```

To enable automatic updates (recommended), append `auto-update`:

```bash
curl -fsSL https://raw.githubusercontent.com/waterstonsltd/CyberAlarmSecureSensor/refs/heads/main/installer/pca-install.sh -o pca-install.sh \
  && echo "fc14139e09d3783d6c6fcd86d9424c1254142484a8aa7776f0213734fb028626  pca-install.sh" | sha256sum --check \
  && sudo bash pca-install.sh <TOKEN> auto-update
```

> The installer defaults to the `stable` tag. Automatic updates will only move you between promoted `stable` builds.

### Docker Compose

If you prefer to manage the deployment yourself, you can use the provided Docker Compose file.

The `docker-compose.yaml` has a published SHA256 hash so you can verify it has not been tampered with:

```
2039c5e84d34be61b9a7f6ffabc94955217ede74a348ffc02d4167408a60bf93
```

```bash
# Create the install directory and set ownership for the container user
mkdir -p /opt/cyberalarm/data
chown 1654:1654 /opt/cyberalarm/data
cd /opt/cyberalarm

# Download and verify the compose file
curl -fsSL https://raw.githubusercontent.com/waterstonsltd/CyberAlarmSecureSensor/refs/heads/main/installer/docker-compose.yaml -o docker-compose.yaml
echo "2039c5e84d34be61b9a7f6ffabc94955217ede74a348ffc02d4167408a60bf93  docker-compose.yaml" | sha256sum --check

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

## Automatic Updates

When you install with the `auto-update` flag, the installer downloads and installs an update script at `/opt/cyberalarm/scripts/update.sh` and registers it as a cron job that runs once per hour. It also installs `jq`, which is a mandatory dependency of the update script used to parse the authoritative hash from the CyberAlarm portal.

The update script is downloaded from this repository at install time, verified against a SHA256 hash embedded in the installer by the CI pipeline, and then stored locally. It is not generated or embedded inline � you can inspect the source at [`installer/update.sh`](installer/update.sh).

The update script's published SHA256 hash is:

```
e4195d174bd514e35e9be6d7add0be981cb5d411d54f369b1c327f1b15d40bcb
```

### What the update script does

Each time it runs, the script fetches `hashes.json` from the CyberAlarm portal and uses it as the source of truth for everything that follows.

For the compose file, it compares the local copy against the expected hash. If they match, no download is needed. If they differ, it downloads the new version and verifies it against the portal hash before replacing the local copy.

It then checks whether the update script itself is current using the same approach. If a newer version is available it downloads and verifies it, replaces the local copy, and logs a message to console. The new version will be picked up on the next scheduled run � the current run continues to completion using the version already in memory.

Next it verifies the signature of every image referenced in the compose file using Cosign, if installed. Any failure aborts the run before anything is pulled.

Finally it pulls the latest images and restarts the service, but only if a newer image was actually downloaded.

If the portal is unreachable the compose file and update script are both left untouched. Without a trusted hash to verify against, downloading either would offer no security guarantee. The script still proceeds to the Cosign and image pull steps. All activity is logged to `/var/log/cyberalarm-update.log`.

### Running the update script manually

If you installed to the default location (`/opt/cyberalarm`), you can run the update script directly with no arguments:

```bash
sudo /opt/cyberalarm/scripts/update.sh
```

If you installed to a custom location, pass the paths explicitly to override the defaults:

```bash
sudo /opt/cyberalarm/scripts/update.sh \
  --install-dir /custom/path \
  --compose-file /custom/path/docker-compose.yml
```

### Verifying the update script

If you want to verify the update script that was installed on your system matches the expected release hash:

```bash
sha256sum /opt/cyberalarm/scripts/update.sh
```

Compare the output against `e4195d174bd514e35e9be6d7add0be981cb5d411d54f369b1c327f1b15d40bcb` (or the current hash shown on the [CyberAlarm portal](https://member.cyberalarm.police.uk)).

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
| **Installer integrity** | SHA256 hashes for the installer, Docker Compose file, and update script are published and embedded at release time by the CI pipeline |

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

If you are a UK police force or public sector organisation interested in deploying CyberAlarm, please contact **enquries@cyberalarm.police.uk**.

## Support

- **Deployment and operational queries:** [cyberalarm.police.uk/contact](https://www.cyberalarm.police.uk/contact)
- **Security vulnerabilities:** see [SECURITY.md](https://github.com/waterstonsltd/CyberAlarmSecureSensor/tree/main?tab=security-ov-file)

## Governance

CyberAlarm is developed by **Waterstons Ltd** in partnership with the **National Police Chiefs' Council (NPCC)**. Technical governance and risk assessment documentation is available to authorised organisations on request.

## Acknowledgements

CyberAlarm is made possible through collaboration between [Waterstons Ltd](https://www.waterstons.com), the [National Police Chiefs' Council](https://www.npcc.police.uk/), UK police forces, and the [National Cyber Security Centre](https://www.ncsc.gov.uk/).
