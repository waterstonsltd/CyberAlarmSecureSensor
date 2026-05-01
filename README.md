# CyberAlarm Secure Sensor

The **CyberAlarm Secure Sensor** is the syslog relay component of the [Police CyberAlarm](https://www.cyberalarm.police.uk) (PCA) platform. It securely collects, encrypts, and forwards syslog data from network devices to the central PCA platform for analysis and threat detection.

This repository contains the source code for the sensor component only. The central processing platform, analytics engines, and other PCA components are not included.

---

## Contents

- [About Police CyberAlarm](#about-police-cyberalarm)
- [Features](#features)
- [Requirements](#requirements)
- [Image Tags](#image-tags)
- [Installation](#installation)
  - [Prerequisites: Install Cosign](#prerequisites-install-cosign)
  - [Recommended: One-Line Installer](#recommended-one-line-installer)
  - [Docker Compose](#docker-compose)
  - [Docker Run](#docker-run)
  - [Windows Service Installer](#windows-service-installer)
- [Configuration](#configuration)
  - [Required](#required)
  - [Commonly Changed](#commonly-changed)
  - [Advanced Tuning](#advanced-tuning)
  - [Example `.env` file](#example-env-file)
  - [Optional file-drop ingestion](#optional-file-drop-ingestion)
- [Encrypted syslog over TLS](#encrypted-syslog-over-tls)
- [TCP/TLS Syslog and Firewall Availability](#tcptls-syslog-and-firewall-availability)
- [Automatic Updates](#automatic-updates)
  - [Windows Service updates](#windows-service-updates)
  - [What the update script does](#what-the-update-script-does)
  - [Running the update manually](#running-the-update-manually)
  - [Disabling automatic updates](#disabling-automatic-updates)
- [Security](#security)
  - [Coordinated Vulnerability Disclosure](#coordinated-vulnerability-disclosure)
  - [Supply Chain Security](#supply-chain-security)
  - [Verifying Image Signatures](#verifying-image-signatures)
  - [Verifying the SBOM](#verifying-the-sbom)
  - [Verifying the Windows installer](#verifying-the-windows-installer)
- [Metrics](#metrics)
- [Compliance](#compliance)
- [License](#license)
- [Contributing](#contributing)
- [Cloud Hosting](#cloud-hosting)
- [Troubleshooting](#troubleshooting)
- [Support](#support)
- [Governance](#governance)
- [Acknowledgements](#acknowledgements)

---

## About Police CyberAlarm

Police CyberAlarm is a free, Home Office-funded cybersecurity monitoring service that helps organisations across the UK monitor and report suspicious cyber activity. The platform is developed by [Waterstons](https://www.waterstons.com) in partnership with the National Police Chiefs' Council (NPCC) and aligns with [NCSC guidance](https://www.ncsc.gov.uk/) on cybersecurity monitoring.

## Features

- **Syslog collection** receives syslog data over UDP and TCP (port 514)
- **End-to-end encryption** RSA-4096 signatures with PSS padding and AES-256-GCM payload encryption
- **Secure transmission** SFTP-based upload to Azure infrastructure
- **Containerised deployment** minimal, production-ready Docker images

> **Security:** If you believe you have found a vulnerability in this software, please do not raise a public GitHub issue. Report it responsibly by following the steps in our [security policy](https://github.com/waterstonsltd/CyberAlarmSecureSensor/tree/main?tab=security-ov-file).

> ⚠️ **Cisco ASA and Firepower users — read before enabling TCP or TLS syslog:** Cisco documents that when TCP syslog is configured and the syslog relay is unreachable, these devices **block all new connections by default**. This means if the relay goes down, your Cisco device may take your internet connectivity with it until the relay recovers or you intervene. Review the mitigation steps in [TCP/TLS Syslog and Firewall Availability](#tcptls-syslog-and-firewall-availability) before enabling TCP or TLS syslog on a Cisco ASA or Firepower device.

## Requirements

- Docker 20.10 or later for Linux container deployments
- A Linux server with a static IP address, or Windows Server 2019 / Windows 10 or later for the Windows service installer
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
> 4dbfb562db1acc72dcd29f983b887dd0ea01948cb68e901a2d97bd9a841b30e0
> ```
> Cross-reference this against the hash shown on the [CyberAlarm portal](https://member.cyberalarm.police.uk) before running.

```bash
curl -fsSL https://raw.githubusercontent.com/waterstonsltd/CyberAlarmSecureSensor/refs/heads/main/installer/pca-install.sh -o pca-install.sh \
  && echo "4dbfb562db1acc72dcd29f983b887dd0ea01948cb68e901a2d97bd9a841b30e0  pca-install.sh" | sha256sum --check \
  && sudo bash pca-install.sh <TOKEN>
```

To enable automatic updates (recommended), append `auto-update`:

```bash
curl -fsSL https://raw.githubusercontent.com/waterstonsltd/CyberAlarmSecureSensor/refs/heads/main/installer/pca-install.sh -o pca-install.sh \
  && echo "4dbfb562db1acc72dcd29f983b887dd0ea01948cb68e901a2d97bd9a841b30e0  pca-install.sh" | sha256sum --check \
  && sudo bash pca-install.sh <TOKEN> auto-update
```

> The installer defaults to the `stable` tag. Automatic updates will only move you between promoted `stable` builds.

### Docker Compose

If you prefer to manage the deployment yourself, you can use the provided Docker Compose file.

The `docker-compose.yaml` has a published SHA256 hash so you can verify it has not been tampered with:

```
e0ffd098e1d038bbab4fd6362ebba9061707824fcc0eb1b0bd23401a84eab136
```

```bash
# Create the install directory and set ownership for the container user
mkdir -p /opt/cyberalarm/data
chown 1654:1654 /opt/cyberalarm/data
cd /opt/cyberalarm

# Download and verify the compose file
curl -fsSL https://raw.githubusercontent.com/waterstonsltd/CyberAlarmSecureSensor/refs/heads/main/installer/docker-compose.yaml -o docker-compose.yaml
echo "e0ffd098e1d038bbab4fd6362ebba9061707824fcc0eb1b0bd23401a84eab136  docker-compose.yaml" | sha256sum --check

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

### Windows Service Installer

The recommended Windows install path mirrors the Linux installer flow: download the PowerShell installer script, verify its SHA256 hash, then run it with your registration token.

> **Security notice:** always verify the PowerShell installer's integrity before execution. The SHA256 hash of the current Windows installer script is:
> ```
> 794f7d45b93c17eaa0cbd56c3792c61df4b04d0f701b62e4853426b68d8c0a61
> ```
> Cross-reference this against the hash shown on the [CyberAlarm portal](https://member.cyberalarm.police.uk) before running.

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/waterstonsltd/CyberAlarmSecureSensor/refs/heads/main/installer/Install-CyberAlarmSecureSensor.ps1" -OutFile "Install-CyberAlarmSecureSensor.ps1"
if ((Get-FileHash .\Install-CyberAlarmSecureSensor.ps1 -Algorithm SHA256).Hash.ToLowerInvariant() -ne "794f7d45b93c17eaa0cbd56c3792c61df4b04d0f701b62e4853426b68d8c0a61") {
  throw "Installer script hash mismatch. Download a fresh command from the CyberAlarm portal."
}

powershell -ExecutionPolicy Bypass -File .\Install-CyberAlarmSecureSensor.ps1 -RegistrationToken "<TOKEN>"
```

For non-production environments, pass `-Environment dev` or `-Environment uat`:

```powershell
powershell -ExecutionPolicy Bypass -File .\Install-CyberAlarmSecureSensor.ps1 -RegistrationToken "<TOKEN>" -Environment uat
```

To install the latest pre-release build instead of the current stable version, add `-PreRelease`. This is the Windows equivalent of switching a Docker deployment from `:stable` to `:latest`:

```powershell
powershell -ExecutionPolicy Bypass -File .\Install-CyberAlarmSecureSensor.ps1 -RegistrationToken "<TOKEN>" -PreRelease
```

> **Note:** Pre-release builds have not completed the full validation period. Use them for evaluation or testing only, not in production.

To fully remove a Windows installation, run the same script with `-Uninstall`:

```powershell
powershell -ExecutionPolicy Bypass -File .\Install-CyberAlarmSecureSensor.ps1 -Uninstall
```


The PowerShell installer will:

1. Download the latest `CyberAlarmSecureSensor-win.msi` from the [GitHub Releases](https://github.com/waterstonsltd/CyberAlarmSecureSensor/releases) page.
2. Verify the MSI Authenticode signature and expected Waterstons publisher.
3. Install the relay as the `CyberAlarm Syslog Relay` Windows service.
4. Write `%ProgramData%\syslog-relay\appsettings.windows.local.json` with your registration token and the `ApiBaseUrl` derived from the selected environment.
5. Restart the service so the updated configuration is applied.
6. Create inbound Windows Firewall rules allowing TCP and UDP traffic on port 514 (`CyberAlarm Secure Sensor - Syslog (TCP)` and `CyberAlarm Secure Sensor - Syslog (UDP)`). If the rules already exist they are left unchanged, so re-running the installer is safe.

The `CyberAlarmSecureSensor-win-Setup.exe`, `.nupkg`, `RELEASES`, and JSON files on the release are update assets used by Velopack. For a new Windows service installation, use `CyberAlarmSecureSensor-win.msi`.

Once installed, the service starts automatically on boot. Logs are written to `%ProgramData%\syslog-relay\logs\`.

#### Managing the Windows service

If you need to check whether the relay is running, or start and stop it manually, use the instructions below.

For Windows Server with a GUI:

1. Open `Services` from the Start menu, or run `services.msc`.
2. Find `CyberAlarm Syslog Relay` in the list.
3. Check the `Status` column to confirm whether it is `Running` or blank/stopped.
4. Use the actions in the right-hand pane, or right-click the service, to `Start`, `Stop`, or `Restart` it.

For Windows Server Core or any Windows host using PowerShell:

Check whether the service exists and whether it is running:

```powershell
Get-Service -Name "CyberAlarm Syslog Relay"
sc.exe query "CyberAlarm Syslog Relay"
```

Start the service manually:

```powershell
Start-Service -Name "CyberAlarm Syslog Relay"
# or
sc.exe start "CyberAlarm Syslog Relay"
```

Stop the service manually:

```powershell
Stop-Service -Name "CyberAlarm Syslog Relay"
# or
sc.exe stop "CyberAlarm Syslog Relay"
```

Restart the service manually:

```powershell
Restart-Service -Name "CyberAlarm Syslog Relay"
```

If the service fails to start, inspect the relay logs in `%ProgramData%\syslog-relay\logs\` and query the current service state again with `sc.exe query "CyberAlarm Syslog Relay"`.

---

## Configuration

All settings can be supplied as Docker environment variables. In .NET, environment variables override values in `appsettings.json`, and nested keys use `__` as the separator. Use `Serilog__MinimumLevel__Default` to control the log level.

The provided Docker Compose file already passes the most common variables via a `.env` file. Any additional variable below can be added to that file or passed directly in the `environment:` block. If you used the one-line installer, the `.env` file is at `/opt/cyberalarm/.env`.

For Windows installs, edit `%ProgramData%\syslog-relay\appsettings.windows.local.json` instead of using environment variables. The same keys apply.

### Required

| Variable | Description |
|----------|-------------|
| `REGISTRATION_TOKEN` | Your registration token from the [CyberAlarm portal](https://member.cyberalarm.police.uk). The sensor will not start without this. |

### Commonly Changed

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `Information` | Controls log verbosity. Accepted values: `Trace`, `Debug`, `Information`, `Warning`, `Error`, `Critical`, `None`. Use `Debug` for troubleshooting, `Warning` to reduce noise in production. |
| `AdditionalLocalSubnet` | *(empty)* | A CIDR subnet to treat as local, in addition to the standard RFC 1918 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`). Events where both source and destination IPs fall within a local subnet are not uploaded. Example: `AdditionalLocalSubnet=192.0.2.0/24`. |
| `MaximumTcpClients` | `20` | Maximum number of simultaneous TCP connections accepted on port 514. Additional connections are immediately disconnected. Increase if you have many syslog sources connecting over TCP. |
| `UploadRawLogs` | `false` | When `true`, all events are uploaded with their raw syslog lines. This is primarily for troubleshooting router parsing issues. When `false`, only successfully parsed events are uploaded. |
| `FileWatcherEnabled` | `false` | Enables ingestion from a mounted drop folder. When `true`, the sensor requires `FileWatcherDropPath` to exist at startup and will fail fast if the mount is missing or incorrect. |
| `FileWatcherDropPath` | `/mnt/drop` | Path to a directory the sensor watches for syslog files to ingest (drop folder pattern). This is only used when `FileWatcherEnabled=true`. |
| `TlsEnabled` | `false` | Set to `true` to enable encrypted syslog (RFC 5425) on port 6514. See [Encrypted syslog over TLS](#encrypted-syslog-over-tls) for all TLS variables and certificate setup. |

### Advanced Tuning

These settings have sensible defaults and do not normally need to be changed.

| Variable | Default | Description |
|----------|---------|-------------|
| `UploadIntervalInMinutes` | `60` | How often the upload cycle runs — file selection, grouping, bundling, and upload to the central platform. |
| `ChannelCapacity` | `100000` | Size of the bounded in-memory channel buffers between pipeline stages. If a downstream stage falls behind, upstream stages will apply back-pressure. Reduce on memory-constrained hosts. |
| `PersistenceBufferSize` | `1000` | Number of parsed events held in memory before being flushed to disk. |
| `PersistenceBufferIntervalInSeconds` | `60` | Maximum time (seconds) between disk flushes. Events are flushed when either this interval or `PersistenceBufferSize` is reached, whichever comes first. |
| `PatternMatchingScanLength` | `300` | Number of characters from the start of each syslog message that are scanned when evaluating `ContainsAll`/`ContainsAny` pattern rules. Limits the search window to improve throughput. |
| `PatternMatchingCacheDurationInSeconds` | `3600` | How long the compiled pattern matcher is cached before being rebuilt from the latest status response. |
| `FileWatcherIntervalInSeconds` | `3600` | How often the file watcher scans `FileWatcherDropPath` for new files. |
| `FileWatcherMaximumRetryCount` | `5` | Number of times a file in the drop folder will be retried before being permanently skipped. |
| `RawGroupedLogsMaxFileSizeBytes` | `5368709120` | Maximum size in bytes of a single grouped raw log file before it is rolled to a new file. Default is 5 GB. |
| `EnableRequestLogging` | `false` | When `true`, logs outgoing HTTP request details at Debug level. Only non-sensitive fields are included. Set to `true` when troubleshooting registration or connectivity issues. |
| `ApiBaseUrl` | *(set by installer environment)* | Base URL of the CyberAlarm API (for example `https://api.cyberalarm.police.uk`, `https://dev-api.cyberalarm.police.uk`, or `https://uat-api.cyberalarm.police.uk`). The PowerShell installer selects this from `-Environment`, and the status and registration endpoints are derived from it. |
| `ParseFailureLogIntervalInMinutes` | `60` | How often parse failures are logged. Repeated failures for the same pattern are suppressed and summarised at this interval to avoid flooding logs. |
| `PatternMatchingDegreeOfParallelism` | `Environment.ProcessorCount` | Number of parallel workers used for pattern matching. Defaults to the number of CPU cores available to the container. |
| `ParsingDegreeOfParallelism` | `Environment.ProcessorCount` | Number of parallel workers used to parse incoming syslog events. Defaults to the number of CPU cores available to the container (respects Docker `cpus` limits). For live syslog relay, the default is sufficient. See [Bulk file ingestion performance](#bulk-file-ingestion-performance) for guidance on large file processing. |
| `ValidationDegreeOfParallelism` | `Environment.ProcessorCount` | Number of parallel workers used for event validation. Defaults to the number of CPU cores available to the container. |

### Example `.env` file

```env
# Required
REGISTRATION_TOKEN=your-token-here

# Optional overrides
LOG_LEVEL=Information
AdditionalLocalSubnet=192.0.2.0/24
MaximumTcpClients=5
UploadIntervalInMinutes=30
FileWatcherEnabled=true
```

### Optional file-drop ingestion

File-drop ingestion is disabled by default.

To enable it with Docker Compose, add a second volume mount and set the file watcher options:

```yaml
services:
  syslog-relay:
    volumes:
      - ./data:/var/lib/syslog-relay:rw
      - ./drop:/mnt/drop:rw
    environment:
      - FileWatcherEnabled=true
```

To enable it with `docker run`:

```bash
docker run -d \
  --name syslog-relay \
  --restart unless-stopped \
  -v ./data:/var/lib/syslog-relay:rw \
  -v ./drop:/mnt/drop:rw \
  -p 514:514/udp \
  -p 514:514/tcp \
  -e REGISTRATION_TOKEN=<TOKEN> \
  -e FileWatcherEnabled=true \
  ghcr.io/waterstonsltd/cyberalarm-securesensor:stable
```

If `FileWatcherEnabled=true` and `/mnt/drop` is not mounted correctly, the sensor fails at startup so the configuration issue is visible immediately. You only need to set `FileWatcherDropPath` if you want a different in-container mount target.

---

## Encrypted syslog over TLS

The relay supports RFC 5425 encrypted syslog on TCP port **6514**. TLS is opt-in — it is disabled by default and does not affect the standard UDP/TCP listeners on port 514.

Two modes are available:

- **Server-only TLS** — encrypts the connection; the firewall does not need a client certificate.
- **Mutual TLS (mTLS)** — additionally requires the firewall to authenticate with a client certificate issued by an operator-supplied CA.

You supply your own certificates. See [docs/tls.md](docs/tls.md) for certificate generation, Docker Compose configuration, and a smoke-test procedure.

| Variable | Default | Description |
|---|---|---|
| `TlsEnabled` | `false` | Set to `true` to start the TLS listener. |
| `AllowPlaintextListenersWhenTlsEnabled` | `false` | When `TlsEnabled=true`, keeps the UDP/TCP listeners on port 514 enabled. Leave this `false` to disable plaintext syslog by default when TLS is enabled. |
| `TlsCertificatePath` | `/certs/server.pfx` | Path to the server PKCS#12 file inside the container. |
| `TlsCertificatePassword` | *(empty)* | Password protecting the PKCS#12 file. |
| `TlsRequireClientCertificate` | `false` | Set to `true` to require mutual TLS. |
| `TlsClientCaCertificatePath` | `/certs/ca.crt` | CA certificate used to validate client certificates (mutual TLS only). |
| `TlsPort` | `6514` | TCP port for the TLS listener inside the container. Most deployments should leave this unchanged and, if needed, change the Docker port mapping instead. |

---

## TCP/TLS Syslog and Firewall Availability

When a firewall is configured to send syslog over **TCP** (including TLS syslog), some devices are documented to **block all new connections** if the remote syslog server becomes unreachable. This is a per-vendor design choice and is not universal.

| Vendor | Product | Documented fail-closed behaviour | Mitigation |
|---|---|---|---|
| Cisco | ASA | **Confirmed.** Cisco documents that when TCP syslog is configured and the server is inaccessible, the ASA blocks all new connections by default. | Enable `logging permit-hostdown` on the ASA. |
| Cisco | Firepower / FTD | **Confirmed.** FTD documentation describes that network traffic through the device can be denied when the TCP syslog server is down. | Enable *Allow user traffic to pass when TCP syslog server is down* in FMC Platform Settings. |
| Barracuda | CloudGen Firewall | Not found in vendor documentation. | Verify behaviour in a test environment before production use. |
| Cisco | Meraki MX | **Not applicable — UDP syslog only.** Meraki MX does not support TCP or TLS syslog; this warning does not apply. | Use UDP syslog (port 514). |
| DrayTek | Vigor | **Not applicable — UDP syslog only.** Vigor syslog is UDP-only in standard firmware; this warning does not apply. | Use UDP syslog (port 514). |
| Fortinet | FortiGate | Not found in vendor documentation. | Verify behaviour in a test environment before production use. |
| Palo Alto | PAN-OS | Not found in vendor documentation. | Verify behaviour in a test environment before production use. |
| Netgate | pfSense | Not found in vendor documentation (pfSense uses UDP by default; TCP requires `syslog-ng`). | Verify behaviour in a test environment before production use. |
| Smoothwall | Firewall | Not found in vendor documentation. | Verify behaviour in a test environment before production use. |
| Sophos | UTM / XG | Not found in vendor documentation. | Verify behaviour in a test environment before production use. |
| Ubiquiti | UniFi | **Not applicable — UDP syslog only.** UniFi does not support TCP or TLS syslog; this warning does not apply. | Use UDP syslog (port 514). |
| WatchGuard | Firebox / Dimension | Not found in vendor documentation. | Verify behaviour in a test environment before production use. |

*"Not found in vendor documentation"* means no authoritative statement has been found confirming fail-closed behaviour — it does not guarantee the device is safe to use without testing.

---

## Automatic Updates

### Windows Service updates

Windows installs update automatically in the background. No cron job or scheduled task is required. The service periodically checks for new releases, downloads the update package, and exits so Velopack can apply the update and restart the service automatically.

### Running a Windows update manually

If the automatic update path fails, update the Windows install manually with the latest MSI from the release you want to deploy.

1. Check the current installed version and service state:

```powershell
Get-Service -Name "CyberAlarm Syslog Relay"
Get-Item "C:\ProgramData\syslog-relay\appsettings.windows.local.json"
```

2. Download `CyberAlarmSecureSensor-win.msi` from the required GitHub release.

3. Verify the MSI signature before running it:

```powershell
$sig = Get-AuthenticodeSignature .\CyberAlarmSecureSensor-win.msi
$sig.Status
$sig.SignerCertificate.Subject
$sig.TimeStamperCertificate.Subject
```

4. Install the MSI over the top of the existing install:

```powershell
msiexec /i .\CyberAlarmSecureSensor-win.msi /qn /norestart
```

5. Restart the service and confirm it is running:

```powershell
Restart-Service -Name "CyberAlarm Syslog Relay"
Get-Service -Name "CyberAlarm Syslog Relay"
```

The relay configuration lives in `%ProgramData%\syslog-relay\appsettings.windows.local.json`, so a manual MSI update does not require a new token if you are keeping the same registration and environment.

If you need to change the token, change the environment, or recreate a missing service, rerun the PowerShell installer instead of using `msiexec` directly:

```powershell
powershell -ExecutionPolicy Bypass -File .\Install-CyberAlarmSecureSensor.ps1 -RegistrationToken "<TOKEN>" -Environment prod
```

Add `-PreRelease` if you are intentionally moving the machine to the latest pre-release channel.

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
| **Installer integrity** | SHA256 hashes for the Linux installer, Windows PowerShell installer, and Docker Compose file are published at release time by the CI pipeline |
| **Windows installer provenance** | The Windows install path relies on the published PowerShell script hash before execution, and the MSI should present a valid Authenticode signature from the Waterstons publisher |

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

### Verifying the Windows installer

There are two separate checks for the Windows install path:

1. Verify the PowerShell installer script SHA256 before you run it.
2. Check that the MSI is Authenticode-signed by the expected Waterstons publisher.

Manual MSI signature inspection:

```powershell
$sig = Get-AuthenticodeSignature .\CyberAlarmSecureSensor-win.msi
$sig.Status
$sig.SignerCertificate.Subject
$sig.TimeStamperCertificate.Subject
```

A valid installer should report `Valid` and show a signer subject containing `Waterstons`.

The Windows service writes logs to `%ProgramData%\syslog-relay\logs\`.

---

## Metrics

The sensor exposes internal pipeline metrics using the standard .NET `System.Diagnostics.Metrics` API. No extra packages are required and metrics collection has no effect on performance when not actively observed.

The following metrics are available under two meters:

**`CyberAlarm.SyslogRelay.Pipeline`** — processing pipeline

| Metric | Type | Tags | Description |
|--------|------|------|-------------|
| `pipeline.stage.processing_duration` (ms) | Histogram | `stage` | Time taken to process a single event in a stage |
| `pipeline.stage.items_processed` | Counter | `stage` | Total events processed by a stage |
| `pipeline.channel.pending_items` ({items}) | Gauge | `stage` | Events currently queued waiting to enter a stage |
| `pipeline.validation.outcomes` | Counter | `outcome` | Events classified by outcome: `Success`, `UnableToPatternMatch`, `UnableToParse`, `LocalOnlyEvent` |
| `pipeline.buffer.flushes` | Counter | `reason` | Buffer flushes by trigger: `SizeReached`, `TimeElapsed`, `StoppingStage` |
| `pipeline.buffer.flush_size` ({events}) | Histogram | — | Number of events written to disk per flush |

**`CyberAlarm.SyslogRelay.Upload`** — upload cycle

| Metric | Type | Description |
|--------|------|-------------|
| `upload.files_uploaded` | Counter | Files successfully uploaded to the platform |
| `upload.files_failed` | Counter | Files that failed to upload |
| `upload.cycle_duration` (ms) | Histogram | Total time for a complete upload cycle |

For instructions on viewing metrics locally, setting up dotnet-monitor, and running a full Grafana dashboard, see [docs/metrics/METRICS.md](docs/metrics/METRICS.md).

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

If you are interested in deploying CyberAlarm, please contact **enquiries@cyberalarm.police.uk**.

## Cloud Hosting

The relay can be deployed on a cloud VM or a managed container service. See [docs/cloud-hosting.md](docs/cloud-hosting.md) for deployment patterns covering site-to-site VPN, TLS syslog, Azure Container Instances, AWS Fargate, and IP access restrictions.

---

## Troubleshooting

If the portal shows **"no data yet"** after installation, or a Windows service update needs manual recovery, see [docs/troubleshooting.md](docs/troubleshooting.md) for step-by-step guidance covering Windows service checks, manual MSI recovery, log inspection, data folder checks, and connectivity tests.

---

## Support

- **Deployment and operational queries:** [cyberalarm.police.uk/contact](https://www.cyberalarm.police.uk/contact)
- **Security vulnerabilities:** see [SECURITY.md](https://github.com/waterstonsltd/CyberAlarmSecureSensor/tree/main?tab=security-ov-file)

## Governance

CyberAlarm is developed by **Waterstons Ltd** in partnership with the **National Police Chiefs' Council (NPCC)**. Technical governance and risk assessment documentation is available to authorised organisations on request.

## Acknowledgements

CyberAlarm is made possible through collaboration between [Waterstons Ltd](https://www.waterstons.com), the [National Police Chiefs' Council](https://www.npcc.police.uk/), and the [National Cyber Security Centre](https://www.ncsc.gov.uk/).
