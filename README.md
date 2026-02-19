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
- A registration token for the from the Police CyberAlarm website (https://portal.cyberalam.police.uk)

## Deployment

Detailed deployment instructions are available in the [docs/deployment.md](docs/deployment.md) file.

### Quick Start (Docker)

```bash
# Pull the latest image
docker pull TBD/cyberalarm-secure-sensor:latest

# Run with environment configuration
docker run -d \
  --name cyberalarm-sensor \
  -p 514:514/udp \
  -p 514:514/tcp \
  -e REGISTRATION_TOKEN=REPLACE WITH YOUR TOKEN
  TBD/cyberalarm-secure-sensor:latest
```

Full configuration options and production deployment guidance are documented in the deployment guide.

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
- **Software Bill of Materials (SBOM)** - Available in `SBOM.json`
- **Signed binaries** - All published Docker images are signed with our official certificate
- **Static analysis** - All releases undergo automated security scanning before publication

### Verification

Docker images can be verified using the provided SHA-256 checksums:

```bash
# Download checksum file
curl -O https://github.com/waterstons/cyberalarm-secure-sensor/releases/latest/checksums.txt

# Verify image
docker pull npccprdcontainersukacr.azurecr.io/cyberalarm-secure-sensor:1.0.0
docker images --digests | grep cyberalarm-secure-sensor
# Compare digest with checksums.txt
```

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