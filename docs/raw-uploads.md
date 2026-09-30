# Raw uploads

Raw uploads is a troubleshooting mode that causes the relay to include the original syslog line with every uploaded event, and to upload events that would otherwise be silently dropped.

It is disabled by default and is not intended for permanent use.

---

## What data is uploaded by default?

By default, the relay only uploads **metadata from inbound traffic** — connections originating from external IPs targeting your internal network. The following event types are filtered locally and **never uploaded**:

| Event type | Description | Why it is filtered |
|---|---|---|
| Local-only events | Traffic between two RFC 1918 private addresses (e.g. `192.168.1.10` → `192.168.1.20`) | Internal LAN traffic is not relevant to threat detection |
| Outbound events | Traffic from an internal IP to an external IP (e.g. `192.168.1.10` → `8.8.8.8`) | Outbound traffic is filtered by default; enable `UploadOutboundData=true` if you want to include it |

> **Privacy note:** Because local and outbound traffic are filtered at the relay, this data never leaves your network unless you explicitly enable raw uploads or outbound data upload.

---

## What changes when raw uploads is enabled

| | Default (`UploadRawLogs=false`) | Raw uploads enabled |
|---|---|---|
| Successfully parsed inbound events | Uploaded (parsed fields only) | Uploaded (parsed fields + raw syslog line) |
| Outbound events (internal → external) | Dropped (unless `UploadOutboundData=true`) | Uploaded with raw syslog line |
| Events that could not be pattern-matched | Dropped | Uploaded with raw syslog line |
| Events that could not be parsed | Dropped | Uploaded with raw syslog line |
| Local-only events (traffic between RFC 1918 addresses) | Dropped | Uploaded with raw syslog line |
| Ignored events | Dropped | Uploaded with raw syslog line |

When raw uploads is on, every syslog line the relay receives is forwarded to the platform — including lines from device types that are not yet supported.

> **Privacy note:** Raw syslog lines may contain hostnames, usernames, or other information from your network. Only enable this mode when requested by the CyberAlarm support team or when actively diagnosing a parsing problem.

---

## When to use it

Raw uploads is useful when:

- A device is sending syslog but its events are not appearing on the portal and you suspect a parsing failure.
- The CyberAlarm support team has asked you to enable it to collect sample data for a new or broken parser.

It is **not** a substitute for a correctly configured parser and should be turned off again once the issue is resolved.

---

## Turning raw uploads on

### Windows service

Edit `%ProgramData%\syslog-relay\appsettings.windows.local.json` and set:

```json
{
  "UploadRawLogs": true
}
```

Then restart the service:

```powershell
Restart-Service "CyberAlarm Syslog Relay"
```

### Docker Compose (recommended)

Add `UploadRawLogs=true` to your `.env` file (normally at `/opt/cyberalarm/.env`):

```env
UploadRawLogs=true
```

Then restart the container to apply the change:

```bash
cd /opt/cyberalarm
docker compose up -d
```

### Docker run

Pass the environment variable directly:

```bash
sudo docker run -d \
  --name syslog-relay \
  --restart unless-stopped \
  -v ./data:/var/lib/syslog-relay:rw \
  -p 514:514/udp \
  -p 514:514/tcp \
  -e REGISTRATION_TOKEN=<TOKEN> \
  -e UploadRawLogs=true \
  ghcr.io/waterstonsltd/cyberalarm-securesensor:stable
```

### Confirming the setting is active

After the container restarts, check the startup log to confirm the value was picked up:

```bash
cd /opt/cyberalarm
docker compose logs syslog-relay | grep -i "rawlog\|UploadRawLogs"
```

---

## Turning raw uploads off

Remove (or set to `false`) the `UploadRawLogs` line in `.env`:

```env
UploadRawLogs=false
```

Then restart:

```bash
cd /opt/cyberalarm
docker compose up -d
```

The setting takes effect from the next upload cycle. Previously uploaded raw events are not removed from the platform.
