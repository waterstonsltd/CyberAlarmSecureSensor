**TODO** this is just a placeholder for now.

# CyberAlarm Secure Sensor

The **CyberAlarm Secure Sensor** is the syslog relay component of the Police Cyber Alarm (PCA) platform, designed to securely collect, encrypt, and forward syslog data from network devices to the central PCA platform for analysis and threat detection.

This repository contains the source code for the sensor component only. The central processing platform, analytics engines, and other PCA components are not included and remain proprietary.

## About Police Cyber Alarm

Police CyberAlarm (PCA) is a cybersecurity monitoring service provided to UK police forces and public sector organisations, helping detect and respond to cyber threats in real-time. The platform is developed by Waterstons in partnership with the National Police Chiefs' Council (NPCC) and aligns with NCSC guidance on cybersecurity monitoring.

## What This Repository Contains

This repository includes:

- **Syslog relay service** - Receives syslog data from network devices
- **Encryption and signing** - RSA-4096 signatures with PSS padding and AES-256-GCM encryption
- **Secure transmission** - SFTP-based upload to Azure infrastructure
- **Docker containerisation** - Production-ready container images
- **Documentation** - Deployment guides and configuration references

## System Requirements

- Docker 20.10 or later
- Network connectivity to target syslog sources
- A Linux server with a static IP
- A registration token from the Police CyberAlarm website (https://member.cyberalarm.police.uk)

## Deployment

Detailed deployment instructions are available in the [docs/deployment.md](docs/deployment.md) file.

### Quick Start (Linux)

> **Security notice:** Before running any install script, you should verify its integrity. The SHA256 hash of the current installer is:
> ```
> 3d6b1d31c17ecbb9c31f2fa70dc1871f7c32fb98e388a4a7267ad55b4be03e59
> ```
> This hash is also displayed on the [CyberAlarm portal](https://member.cyberalarm.police.uk) next to your install command. Always cross-reference against the portal before running.

**One-line install** (downloads, verifies, and runs in a single step):
```bash
curl -fsSL https://raw.githubusercontent.com/waterstonsltd/CyberAlarmSecureSensor/refs/heads/main/installer/pca-install.sh -o pca-install.sh \
  && echo "3d6b1d31c17ecbb9c31f2fa70dc1871f7c32fb98e388a4a7267ad55b4be03e59  pca-install.sh" | sha256sum --check \
  && sudo bash pca-install.sh <TOKEN>
```

With auto-update enabled:
```bash
curl -fsSL https://raw.githubusercontent.com/waterstonsltd/CyberAlarmSecureSensor/refs/heads/main/installer/pca-install.sh -o pca-install.sh \
  && echo "3d6b1d31c17ecbb9c31f2fa70dc1871f7c32fb98e388a4a7267ad55b4be03e59  pca-install.sh" | sha256sum --check \
  && sudo bash pca-install.sh <TOKEN> auto-update
```

Or as a pipe (without saving the script locally):
```bash
curl -fsSL https://raw.githubusercontent.com/waterstonsltd/CyberAlarmSecureSensor/refs/heads/main/installer/pca-install.sh | sudo bash -s -- <TOKEN> [auto-update]
```
> Note: The pipe form cannot verify the installer hash before execution. We recommend the download-then-verify approach above for security-conscious environments.

### Quick Start (Docker)

You must ensure the data directory can be written to by user `1654` (the container's application user). Create and permission it first:

```bash
mkdir -p ./data
chown 1654:1654 ./data
```

Then run the container:

```bash
docker run -d \
  --name syslog-relay \
  --restart unless-stopped \
  -v ./data:/var/lib/syslog-relay:rw \
  -p 514:514/udp \
  -p 514:514/tcp \
  -e REGISTRATION_TOKEN=<TOKEN> \
  ghcr.io/waterstonsltd/cyberalarm-securesensor:stable
```

However we recommend using Docker Compose. You can find an example `docker-compose.yaml` file at [installer/docker-compose.yaml](installer/docker-compose.yaml).

### Manual Docker Compose Install

The `docker-compose.yaml` file has a published SHA256 hash that you can use to verify it has not been tampered with before deploying. The current hash is:

```
2039c5e84d34be61b9a7f6ffabc94955217ede74a348ffc02d4167408a60bf93
```

To install manually with verification:

```bash
# Create the install directory and set correct ownership
mkdir -p /opt/cyberalarm/data
chown 1654:1654 /opt/cyberalarm/data
cd /opt/cyberalarm

# Download the compose file
curl -fsSL https://raw.githubusercontent.com/waterstonsltd/CyberAlarmSecureSensor/refs/heads/main/installer/docker-compose.yaml -o docker-compose.yaml

# Verify the hash before deploying
echo "2039c5e84d34be61b9a7f6ffabc94955217ede74a348ffc02d4167408a60bf93  docker-compose.yaml" | sha256sum --check

# Start the service (only if the hash check passed)
docker compose up -d
```

If the hash check fails, the file may have been tampered with or you may have an outdated install command. Download a fresh command from the [CyberAlarm portal](https://portal.cyberalarm.police.uk).

You must take responsibility for ensuring the container is kept up to date with the latest security patches. Updates can be applied by running `docker compose pull` followed by `docker compose up -d`. We recommend using the auto-update flag in the installer script, which sets up an hourly cron job to handle this automatically.

## Security

### Coordinated Vulnerability Disclosure
**TO BE DEFINED - PLACEHOLDER**

We operate a **Coordinated Vulnerability Disclosure (CVD)** process in accordance with NCSC guidance. If you discover a security vulnerability:

**DO NOT** open a public GitHub issue.

Instead, please report vulnerabilities privately to: **security@cyberalarm.police.uk**

We aim to:
- Acknowledge receipt within 48 hours
- Provide an initial assessment within 5 working days
- Work with you to understand and remediate the issue
- Credit researchers appropriately (unless you prefer to remain anonymous)

### Bug Bounty Programme

We operate a bug bounty programme for responsible security researchers. Details are available at: **[bounty.cyberalarm.police.uk]**

### Supply Chain Security

This project maintains:
- **Software Bill of Materials (SBOM)** - Attached to every container image as a signed attestation
- **Signed container images** - All published Docker images are cryptographically signed using Sigstore Cosign
- **Static analysis** - All releases undergo automated security scanning before publication

### Image Signature Verification

All CyberAlarm Secure Sensor container images are signed using **Sigstore Cosign** with keyless signing. This provides cryptographic proof that images were built by our official GitHub Actions pipeline and have not been tampered with.

#### Install Cosign

First, install Cosign on your system:

```bash
# Download and install cosign
curl -LO https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
chmod +x cosign-linux-amd64
sudo mv cosign-linux-amd64 /usr/local/bin/cosign
```

#### Verify Image Signature

Verify that the container image is authentic and untampered:

```bash
cosign verify \
  --certificate-identity-regexp="https://github.com/waterstonsltd/CyberAlarmSecureSensor/.*" \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  ghcr.io/waterstonsltd/cyberalarm-securesensor:stable
```

**Expected output:** Verification details showing the image was signed by GitHub Actions from the official Waterstons repository.

**What this verifies:**
- ? Image was built by GitHub Actions from the official Waterstons repository
- ? Image has not been tampered with since signing
- ? Signer identity is cryptographically proven via Sigstore's transparency log

#### Download and Verify SBOM (Software Bill of Materials)

The SBOM lists all components, dependencies, and versions included in the container image. It is cryptographically signed and attached as an attestation.

**Verify the SBOM attestation** (recommended - proves authenticity):

```bash
cosign verify-attestation \
  --certificate-identity-regexp="https://github.com/waterstonsltd/CyberAlarmSecureSensor/.*" \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --type cyclonedx \
  ghcr.io/waterstonsltd/cyberalarm-securesensor:stable
```

**Download the SBOM for inspection:**

```bash
# Download and extract the SBOM
cosign download attestation \
  --predicate-type=cyclonedx \
  ghcr.io/waterstonsltd/cyberalarm-securesensor:stable | \
  jq -r '.payload' | base64 -d | jq '.predicate' > sbom.json

# View the SBOM (pretty-printed)
cat sbom.json | jq .
```

The SBOM is in CycloneDX format and includes:
- All runtime dependencies and libraries
- Package versions and licenses
- Vulnerability metadata
- Build provenance information

#### Verify Image Digest

For additional verification, you can check the cryptographic digest of the image:

```bash
# Pull the image
docker pull ghcr.io/waterstonsltd/cyberalarm-securesensor:stable

# Get the digest
docker inspect --format='{{index .RepoDigests 0}}' ghcr.io/waterstonsltd/cyberalarm-securesensor:stable
```

Compare the digest against what is shown in the Cosign verification output to ensure you're running the exact image that was signed.

## Compliance

The CyberAlarm Secure Sensor is designed for deployment in environments requiring:

- **NCSC compliance** - Aligned with NCSC cybersecurity guidance
- **HMG security standards** - Appropriate for UK government and law enforcement use
- **Risk Management and Accreditation Document Set (RMADS)** - Available to authorised organisations upon request

## License

This project is released under the **Business Source License 1.1**.

Key points:
- **Source available** - You can view, inspect, and modify the code
- **Permitted use** - Non-commercial deployment within UK law enforcement and policing organisations for cybersecurity monitoring
- **Restrictions apply** - Commercial use, redistribution, and SaaS offerings require a commercial license
- **Future open source** - Converts to Apache License 2.0 on 2030-02-17

See [LICENSE](LICENSE) for full terms.

## Contributing

This repository is **read-only** for external users. We do not accept pull requests or external contributions at this time.

If you're a UK police force or public sector organisation interested in deploying the CyberAlarm platform, please contact: **info@cyberalarm.police.uk**

## Documentation



## Support

For deployment support and operational queries:
- **Contact Us**: https://www.cyberalarm.police.uk/contact
- **Documentation**: [docs.cyberalarm.police.uk]

For security vulnerabilities, use the CVD process described above.

## Governance

This project is developed by **Waterstons Ltd** in partnership with the **National Police Chiefs' Council (NPCC)**.

Technical governance and risk assessment documentation (RMADS) is available to authorised organisations on request.

## Acknowledgments

CyberAlarm is made possible through collaboration between:
- Waterstons Ltd (development and platform operations)
- National Police Chiefs' Council (NPCC)
- UK Police Forces (operational deployment and feedback)
- National Cyber Security Centre (NCSC) (guidance and standards)

---

**Version**: 1.0.0  
**Last Updated**: February 2026  
**Maintained by**: Waterstons Ltd
