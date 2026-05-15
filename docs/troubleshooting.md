# Troubleshooting: "No data yet" on the CyberAlarm portal

For Windows service deployments, use the same ingest and upload checks below, but replace Docker-specific commands with the Windows service and log locations listed in [Windows service quick checks](#windows-service-quick-checks).

> **Allow at least one hour after installation before troubleshooting.**
> The relay uploads on a 60-minute cycle. Even when everything is working correctly, the portal will show "no data yet" until the first upload cycle completes. If it has been less than an hour since install, wait and check again before proceeding.

---

## Built-in diagnostics commands

The sensor binary includes two commands for diagnosing issues without manually inspecting files.

### `--diagnostics`

Reads local state, health, and log files, runs live TCP connectivity probes, and prints a report. Exits immediately without starting the sensor.

By default the output is **focused**: only sections with a problem are shown, so you can see immediately what needs fixing. If everything looks healthy you will see:

```
  ✓  All checks passed.

  Run with --full for a complete diagnostic report.
```

Add `--full` to see every section regardless of status — useful for sharing with support or for a routine health check.

**Windows** (run from the install directory, or with the full path):

```powershell
# Focused (problems only — default):
& "C:\Program Files\CyberAlarmSecureSensor\current\CyberAlarm.SyslogRelay.ConsoleApp.exe" --diagnostics

# Full report:
& "C:\Program Files\CyberAlarmSecureSensor\current\CyberAlarm.SyslogRelay.ConsoleApp.exe" --diagnostics --full
```

**Docker:**

```bash
# Focused:
docker run --rm \
  -v /opt/cyberalarm/data:/var/lib/syslog-relay:ro \
  ghcr.io/waterstonsltd/cyberalarm-securesensor:stable \
  --diagnostics

# Full report:
docker run --rm \
  -v /opt/cyberalarm/data:/var/lib/syslog-relay:ro \
  ghcr.io/waterstonsltd/cyberalarm-securesensor:stable \
  --diagnostics --full
```

The full report (`--full`) covers:

| Section | What it shows |
|---|---|
| App Health | Per-service health status from `healthcheck.json` |
| Windows Service | Service running/stopped; guidance if stopped |
| Registration & Upload State | Registered?, upload blocked?, uploads disabled?; root cause from logs if blocked |
| Ingest Pipeline | File counts per `.tmp/` folder; parse stats from newest log file |
| Syslog Source History | Known source IPs from `source-groups/`; TCP connection events from logs |
| Failed Files | Files in `.tmp/failed/` with NDJSON validation results |
| Network | Host IP addresses and listening ports for your syslog sender |
| Windows Firewall | Firewall rule check; port conflict detection |
| Connectivity Probes | Live TCP tests to SFTP (port 22), blob HTTPS (port 443), and the API |
| Recent Log Activity | Last 24 h warnings/errors, deduplicated by message template |

> **Tip:** The `--support-bundle` command always includes the full report, so you do not need to run `--diagnostics --full` separately before raising a ticket.

### `--support-bundle`

Generates a compressed `.zip` file containing the diagnostics report, all application log files, a sample of pipeline data, redacted configuration files, and system information. No private keys or unredacted tokens are included.

**Windows:**

```powershell
& "C:\Program Files\CyberAlarmSecureSensor\current\CyberAlarm.SyslogRelay.ConsoleApp.exe" --support-bundle
```

**Docker:**

```bash
docker run --rm \
  -v /opt/cyberalarm/data:/var/lib/syslog-relay:ro \
  -v /tmp:/tmp \
  ghcr.io/waterstonsltd/cyberalarm-securesensor:stable \
  --support-bundle
# The .zip will be written to /tmp on the host
```

The command prints the full path of the generated file. Send this file to your CyberAlarm support contact or attach it to your support ticket.

---

If the portal still shows **"no data yet"** after an hour, it means the relay has not successfully uploaded any events. There are two distinct causes:

| Root cause | What you see |
|---|---|
| **No ingest** — the relay is not receiving syslog from your network devices | `.tmp` folders stay empty; logs show no incoming events |
| **No upload** — the relay is receiving and persisting data but cannot upload it | `.tmp/upload` accumulates files; logs contain upload errors |

Work through the sections below in order to narrow down which applies.

---

## Windows service quick checks

If you installed the Windows release, the relay runs as the `CyberAlarm Syslog Relay` service instead of a Docker container.

### Check the service status

```powershell
Get-Service "CyberAlarm Syslog Relay"
```

Restart after changing `%ProgramData%\syslog-relay\appsettings.windows.local.json`:

```powershell
Restart-Service "CyberAlarm Syslog Relay"
```

### Manual Windows update recovery

If a Windows auto-update fails or leaves the service stopped on an older version, recover by reinstalling the latest signed MSI over the existing install.

1. Check the current service state:

```powershell
Get-Service "CyberAlarm Syslog Relay"
sc.exe query "CyberAlarm Syslog Relay"
```

2. Download `CyberAlarmSecureSensor-stable.msi` from the GitHub release you want to deploy.

3. Verify the MSI signature before running it:

```powershell
$sig = Get-AuthenticodeSignature .\CyberAlarmSecureSensor-stable.msi
$sig.Status
$sig.SignerCertificate.Subject
$sig.TimeStamperCertificate.Subject
```

4. Reinstall the MSI in place:

```powershell
msiexec /i .\CyberAlarmSecureSensor-stable.msi /qn /norestart
```

5. Restart the service and confirm it is running:

```powershell
Restart-Service "CyberAlarm Syslog Relay"
Get-Service "CyberAlarm Syslog Relay"
```

The relay keeps its configuration in `%ProgramData%\syslog-relay\appsettings.windows.local.json`, so an in-place MSI reinstall preserves the existing registration token and environment.

If you need to change the token, switch between `prod` / `dev` / `uat`, or recreate a missing service, rerun `Install-CyberAlarmSecureSensor.ps1` instead of using `msiexec` directly.

### Check the logs

- Rolling file logs: `%ProgramData%\syslog-relay\logs\`

### Check the data directory

The Windows service writes working files under `%ProgramData%\syslog-relay\`. If the relay is receiving data but not uploading, inspect the same `.tmp` folder structure there that the Docker sections below describe.

### Registration errors on Windows

If the service starts but immediately stops, check the log file in `%ProgramData%\syslog-relay\logs\` for an `Initialisation error` entry. Common registration failures and their resolutions:

| Error message | Cause | Resolution |
|---|---|---|
| `Registration token is not recognised` | The token does not match a provisioned sensor in the CyberAlarm portal | Ensure the sensor has been provisioned via the portal **before** running the installer, then re-run the installer with the correct token |
| `This sensor is already registered` | A previous installation registered this token | If reinstalling, deregister the sensor in the portal first, or reuse the original registration token |
| `The registration token is invalid or has expired` | The token has been revoked or has expired | Generate a new registration token in the portal and re-run the installer |

If none of the above apply, enable debug logging by adding `"Serilog": { "MinimumLevel": { "Default": "Debug" } }` to `%ProgramData%\syslog-relay\appsettings.windows.local.json`, restart the service, and check the log for more detail.

### Port 514 on Windows

The installer automatically creates two inbound Windows Firewall rules (`CyberAlarm Secure Sensor - Syslog (TCP)` and `CyberAlarm Secure Sensor - Syslog (UDP)`) for port 514. If syslog sources cannot connect, verify the rules exist and are enabled:

```powershell
Get-NetFirewallRule -DisplayName "CyberAlarm Secure Sensor*" | Select-Object DisplayName, Enabled, Action
```

If the rules are missing (for example, after a manual install), create them manually:

```powershell
foreach ($proto in 'TCP','UDP') {
    New-NetFirewallRule -DisplayName "CyberAlarm Secure Sensor - Syslog ($proto)" `
        -Direction Inbound -Action Allow -Protocol $proto -LocalPort 514 -Profile Any
}
```

Also check whether another process is already bound to port 514:

```powershell
Get-NetTCPConnection -LocalPort 514 -ErrorAction SilentlyContinue
Get-NetUDPEndpoint -LocalPort 514 -ErrorAction SilentlyContinue
```

If another process is using port 514, it will prevent the relay from starting. Stop or reconfigure that service before starting `CyberAlarm Syslog Relay`.

---

## 1. Check the container is running and healthy

The installer places the Compose file and `.env` at `/opt/cyberalarm`. All commands in this guide assume that working directory.

```bash
cd /opt/cyberalarm
docker compose ps
```

The `syslog-relay` container should be **Up** and report **(healthy)** in the Status column. The health check runs every 30 seconds; allow up to a minute after startup before it first reports.

If the container is not running, start it and follow its logs:

```bash
docker compose up -d
docker compose logs -f syslog-relay
```

Look for startup errors such as missing registration token, write access failures, or volume mount problems. Resolve those before continuing.

---

## 2. Check the logs

### View recent logs

```bash
docker compose logs --tail 200 syslog-relay
```

### Follow logs live

```bash
docker compose logs -f syslog-relay
```

### What to look for

| Log message | Meaning |
|---|---|
| `No files to upload` | Container is running and the upload cycle ran, but nothing has been written to disk yet — ingest may be the problem |
| `Found N files to upload` | Data reached the upload stage — look for success or failure messages that follow |
| `successfully uploaded` | File reached the platform without error |
| `Error uploading <file>` | Individual file upload failed; the file is kept and retried on the next cycle |
| `Critical error while connecting to the server. Stopping application.` | SSH authentication or connection failure — the uploader has stopped; check connectivity and registration token |
| `Storage account name ... contains invalid characters` | Registration state is corrupt; re-register or contact support |

### Increase log verbosity

If the default level is not showing enough detail, set `LOG_LEVEL=Debug` in `/opt/cyberalarm/.env` and restart:

```bash
echo "LOG_LEVEL=Debug" >> /opt/cyberalarm/.env
docker compose up -d
```

Reset to `LOG_LEVEL=Information` once you have finished diagnosing to avoid excessive log output in production.

---

## 3. Inspect the `.tmp` data folder

The relay writes working data to `/opt/cyberalarm/data/.tmp`. This is the in-container path `/var/lib/syslog-relay/.tmp` mounted from the host.

```bash
ls -lh /opt/cyberalarm/data/.tmp/
```

The subfolders and their meanings:

| Folder | Purpose |
|---|---|
| `logs/` | Parsed events buffered for grouping and upload |
| `processing/` | Events currently being grouped; should normally be empty between cycles |
| `source-groups/` | Events grouped by source, awaiting bundling |
| `upload/` | Bundled files ready to upload to the platform |
| `failed/` | Files that could not be processed; manual inspection may be needed |
| `temporaryFiles/` | In-progress working files; normally empty between cycles |

### What the folder state tells you

**All folders empty and staying empty after traffic is sent:**
No ingest is occurring. The relay is not receiving syslog data. Move to [Section 4](#4-test-ingest-from-the-local-server).

**`logs/` or `source-groups/` have content, but `upload/` is empty:**
Data is being ingested and processed. The upload cycle may not have run yet — by default it runs every 60 minutes. Wait for a full cycle or check whether there is an upload error in the logs.

**`upload/` has files that are accumulating over multiple cycles:**
Data is reaching the upload stage but failing to transfer. Check the logs for upload errors (see [Section 2](#2-check-the-logs)) and test outbound connectivity (see [Section 6](#6-test-outbound-upload-connectivity)).

**`failed/` has content:**
Files failed during processing. Check the logs at the time they were created for more detail.

---

## 4. Test ingest from the local server

This test checks that the container is listening and accepting syslog data from the machine it is running on.

> **Note:** A generic test message will not appear as a portal event when `UploadRawLogs=false` (the default), because only messages that match a known device parser are uploaded. Use `.tmp` folder changes and container logs as your proof of ingest.

### Using `logger` (simplest, available on most Linux systems)

**UDP:**
```bash
logger -n 127.0.0.1 -P 514 -d "Test message from $(hostname)"
```

**TCP:**
```bash
logger -n 127.0.0.1 -P 514 -T "Test message from $(hostname)"
```

### Using `nc` / `netcat` (if `logger` is not available)

Install if needed:
```bash
# Debian/Ubuntu
sudo apt install netcat-openbsd

# RHEL/Fedora/CentOS
sudo dnf install nmap-ncat
```

**UDP:**
```bash
echo "<13>$(date '+%b %e %T') $(hostname) test: diagnostic message" | nc -u -w1 127.0.0.1 514
```

**TCP:**
```bash
echo "<13>$(date '+%b %e %T') $(hostname) test: diagnostic message" | nc -q0 127.0.0.1 514
```

### After sending

1. Check the container logs immediately:
   ```bash
   docker compose logs --tail 50 syslog-relay
   ```
2. Check whether any files appeared in `.tmp/logs/`:
   ```bash
   ls -lh /opt/cyberalarm/data/.tmp/logs/
   ```

If files appear in `.tmp/logs/` and the logs show activity, ingest is working. If nothing appears, the container may not be listening correctly — check that port 514 is published (`docker compose ps` should show `0.0.0.0:514->514/udp` and `0.0.0.0:514->514/tcp`).

---

## 5. Test ingest from a remote server

This test checks the network path between a syslog source and the relay. Run the same commands as above from another server on the same network, replacing `127.0.0.1` with the relay server's IP address.

### Using `logger`

```bash
logger -n <RELAY_IP> -P 514 -d "Remote test from $(hostname)"
```

### Using `nc`

**UDP:**
```bash
echo "<13>$(date '+%b %e %T') $(hostname) test: remote diagnostic" | nc -u -w1 <RELAY_IP> 514
```

**TCP:**
```bash
echo "<13>$(date '+%b %e %T') $(hostname) test: remote diagnostic" | nc -q0 <RELAY_IP> 514
```

After sending, check the relay container logs and `.tmp/logs/` as in [Section 4](#4-test-ingest-from-the-local-server).

### Interpreting the results

| Local test | Remote test | Likely cause |
|---|---|---|
| Works | Works | Ingest path is fine — focus on upload path (Sections 2 and 3) |
| Works | Fails | Firewall or routing between the source device and the relay — check host firewall rules and any network firewall on port 514 |
| Fails | Fails | The container listener is the problem — check that the container is healthy, port 514 is published, and no other process is already using port 514 on the host |

### Check for port conflicts on the host

```bash
ss -tulpn | grep ':514'
```

If another process is bound to port 514 the relay cannot start correctly.

### Check the host firewall (iptables / nftables)

```bash
# iptables
sudo iptables -L INPUT -n -v | grep 514

# nftables
sudo nft list ruleset | grep 514
```

If port 514 is blocked, add an allow rule for the source IP ranges you need.

---

## 6. Test outbound upload connectivity

The relay uploads files over **SFTP (port 22 outbound)** to Azure Blob Storage. If the host firewall or a network firewall blocks outbound TCP port 22, every upload cycle will fail with `SshOperationTimeoutException` in the logs and files will accumulate in `.tmp/upload/`.

### Which storage endpoint does this relay use?

The bucket number is the first segment of the registration token in `/opt/cyberalarm/.env`:

```bash
grep REGISTRATION_TOKEN /opt/cyberalarm/.env
# e.g. REGISTRATION_TOKEN=1.abc123.xyz  →  bucket 1
```

The storage endpoints by bucket are:

| Bucket | SFTP hostname |
|--------|---------------|
| 1 | `npccprdsysloguksstraw001.blob.core.windows.net` |
| 2 | `npccprdsysloguksstraw002.blob.core.windows.net` |
| 3 | `npccprdsysloguksstraw003.blob.core.windows.net` |
| 4 | `npccprdsysloguksstraw004.blob.core.windows.net` |
| 5 | `npccprdsysloguksstraw005.blob.core.windows.net` |
| 6 | `npccprdsysloguksstraw006.blob.core.windows.net` |
| 7 | `npccprdsysloguksstraw007.blob.core.windows.net` |
| 8 | `npccprdsysloguksstraw008.blob.core.windows.net` |
| 9 | `npccprdsysloguksstraw009.blob.core.windows.net` |

### Test the connection

Run this from the relay host (replace the hostname with the one for your bucket):

```bash
# Quick TCP connect test — should complete without 'Connection timed out'
timeout 10 bash -c 'cat < /dev/null > /dev/tcp/npccprdsysloguksstraw001.blob.core.windows.net/22' \
  && echo "Port 22 reachable" \
  || echo "Port 22 BLOCKED or unreachable"
```

Or using `nc`:

```bash
nc -z -w 10 npccprdsysloguksstraw001.blob.core.windows.net 22 \
  && echo "Port 22 reachable" \
  || echo "Port 22 BLOCKED or unreachable"
```

If the test times out or reports blocked, the outbound connection is being dropped. Check:

- **Host firewall** — allow outbound TCP port 22 to `*.blob.core.windows.net`:
  ```bash
  # iptables
  sudo iptables -L OUTPUT -n -v | grep 22

  # nftables
  sudo nft list ruleset | grep 22
  ```
- **Network/perimeter firewall** — ensure outbound TCP 22 is permitted from the relay server's IP to Azure UK South (`51.140.0.0/14` and `51.105.0.0/17` cover the relevant ranges, but allowing `*.blob.core.windows.net:22` by hostname is the most reliable approach).

Once connectivity is restored the relay will upload the backlog automatically on the next cycle — no data is lost.

---

## 7. TLS syslog (port 6514)

This section applies only if you have enabled TLS syslog (`TlsEnabled=true`). Standard UDP/TCP on port 514 is unaffected.

### Container reports unhealthy after enabling TLS

Check the container logs for the specific error:

```bash
docker compose logs syslog-relay | grep -i tls
```

Common causes:

| Log message | Cause | Fix |
|---|---|---|
| `no certificate path is configured` | `TlsCertificatePath` is empty or not set | Set `TlsCertificatePath` in your `.env` |
| `certificate path '...' does not exist` | The `.pfx` file is not mounted at the expected path | Check the `./certs:/certs:ro` volume mount and that `server.pfx` is present |
| `Failed to load TLS server certificate` | Wrong password, corrupt file, missing private key, or missing Server Authentication EKU | Verify `TlsCertificatePassword` matches the PKCS#12 password. Regenerate the file if needed and ensure the server certificate includes the `serverAuth` EKU. |
| `requires a client CA certificate path` | `TlsRequireClientCertificate=true` but `TlsClientCaCertificatePath` is empty | Set `TlsClientCaCertificatePath` |
| `client CA certificate path '...' does not exist` | The CA `.crt` file is not at the expected path | Ensure `ca.crt` is in the certs directory and the volume is mounted |

### Handshake failure on the firewall

If the relay is healthy but the firewall reports a TLS handshake error:

1. Verify the firewall trusts the relay's CA. If the relay uses a self-signed certificate, import the CA into the firewall's trusted store.
2. Check the TLS version. The relay accepts TLS 1.2 and 1.3. If the firewall only supports older versions, it will fail to connect.
3. Run the smoke test from `docs/tls.md` to confirm the relay responds correctly.

### Client certificate rejected (mutual TLS)

If the relay logs `TLS authentication failed` for a connecting firewall:

1. Confirm the firewall's client certificate was signed by the CA at `TlsClientCaCertificatePath`. Certificates signed by a different CA will be rejected.
2. Verify the client certificate has the `clientAuth` extended key usage (OID `1.3.6.1.5.5.7.3.2`).
3. Check the certificate has not expired.

### Port 6514 not reachable

Verify the port is open on the host firewall:

```bash
# iptables
sudo iptables -L INPUT -n -v | grep 6514

# nftables
sudo nft list ruleset | grep 6514
```

And confirm the container is listening:

```bash
ss -tlnp | grep 6514
```

---

## 8. Summary: diagnosis decision table

| Container healthy | `.tmp` empty after local test | Remote test fails | Upload errors in logs | Most likely cause |
|---|---|---|---|---|
| No | — | — | — | Container startup failure — check logs for errors |
| Yes | Yes | — | — | No ingest — port 514 not reachable or firewall on the local host |
| Yes | Yes | Yes | — | Firewall between source devices and the relay |
| Yes | No | No | No | Data is ingesting; wait for the upload cycle (default 60 min) |
| Yes | No | No | Yes (`Error uploading`) | Upload connectivity blocked — check outbound port 22 (see [Section 6](#6-test-outbound-upload-connectivity)); files are retried automatically once fixed |
| Yes | No | No | Yes (`Critical error`) | SSH authentication failure — registration token may be invalid; contact support |

---

## Further help

- For deployment and operational queries: [cyberalarm.police.uk/contact](https://www.cyberalarm.police.uk/contact)
- For security vulnerabilities: see [SECURITY.md](../SECURITY.md)
