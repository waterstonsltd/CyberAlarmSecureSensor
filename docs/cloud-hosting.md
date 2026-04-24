# Running the Syslog Relay in the Cloud

The relay is a standard Docker container, so it can run anywhere Docker runs — including cloud-hosted virtual machines and managed container services. This guide covers common cloud deployment patterns, how to securely bridge syslog from your on-premises network devices to a cloud-hosted relay, and what to consider when choosing a hosting approach.

---

## Choosing how to get syslog to the relay

Syslog from your network devices must reach the relay. In a cloud deployment the relay is not on the same LAN as those devices, so you need a transport mechanism. There are three options:

| Option | Best for | Notes |
|---|---|---|
| **Site-to-site VPN** | Organisations with existing VPN infrastructure or a firewall that supports IPsec/IKEv2 | Syslog travels over UDP 514 inside the tunnel — no relay changes needed |
| **WireGuard** | Lightweight, low-overhead encrypted tunnel; ideal when the firewall or a nearby Linux host can run WireGuard | Syslog travels over UDP 514 inside the tunnel — no relay changes needed |
| **TLS syslog (RFC 5425)** | When a tunnel is not practical and the firewall supports encrypted syslog natively | Requires configuring the relay for TLS; see [docs/tls.md](tls.md) |

### Restrict inbound access to your site IP

Regardless of which transport you use, **restrict inbound access to port 514 (and 6514 if using TLS) to your known site IP addresses only.** Never expose the syslog port to the public internet.

Use your cloud provider's network controls to apply this restriction:

- **Azure** — Network Security Group (NSG) inbound rule: allow TCP/UDP 514 (and TCP 6514) from your source IP; deny all other sources.
- **AWS** — Security Group inbound rule: allow TCP/UDP 514 (and TCP 6514) from your source IP.
- **WireGuard** — the relay's syslog port should only be reachable via the WireGuard interface (`wg0`), not the public interface.

---

## Option 1 — Site-to-site VPN

If your firewall already supports a site-to-site VPN (IPsec, IKEv2, or similar) to a cloud gateway, your devices can send syslog to the relay's private IP address inside the tunnel exactly as they would on-premises. No changes to the relay configuration are required.

### Azure

1. Create a **Virtual Network Gateway** (or use **Azure VPN Gateway**) in the same virtual network as the relay.
2. Configure the site-to-site connection to your on-premises firewall.
3. In the virtual network's **Network Security Group**, restrict port 514 to traffic from your on-premises subnet.
4. Point your network devices' syslog destination to the relay's private IP address.

### AWS

1. Create a **Virtual Private Gateway** attached to your VPC, and a **Customer Gateway** for your on-premises device.
2. Set up a **Site-to-Site VPN Connection**.
3. In the **Security Group** attached to the relay instance, restrict port 514 to traffic from your on-premises CIDR.
4. Point your network devices' syslog destination to the relay's private IP address.

---

## Option 2 — WireGuard

WireGuard is a lightweight, high-performance VPN that runs on Linux. If your firewall does not support site-to-site VPN but you have a Linux host at your site (or the firewall itself runs WireGuard), you can establish an encrypted tunnel to the cloud relay host.

### Architecture

```
On-premises:                           Cloud:
  [Firewall] --> syslog UDP 514          [WireGuard server] --> [Relay container]
  [WireGuard peer/client]   <-- tunnel -->
```

The relay's syslog port should only be bound to the WireGuard interface or the private virtual network interface. Do not expose port 514 on the public interface.

### Cloud host setup (brief)

```bash
# Install WireGuard
sudo apt install wireguard

# Generate server keys
wg genkey | tee server_private.key | wg pubkey > server_public.key

# /etc/wireguard/wg0.conf
[Interface]
Address = 10.200.0.1/24
ListenPort = 51820
PrivateKey = <server_private_key>

[Peer]
PublicKey = <client_public_key>
AllowedIPs = 10.200.0.2/32

sudo wg-quick up wg0
```

Expose only UDP 51820 (the WireGuard port) publicly. Restrict it to your site's public IP if possible.

For the relay container, either bind it to `0.0.0.0` and use NSG/Security Group rules to restrict access, or use Docker's `--publish` with the WireGuard interface IP:

```yaml
ports:
  - "10.200.0.1:514:514/udp"
  - "10.200.0.1:514:514/tcp"
```

Your on-premises device sends syslog to `10.200.0.1:514` over the tunnel.

See the [WireGuard documentation](https://www.wireguard.com/quickstart/) for full peer configuration.

---

## Option 3 — TLS syslog

If your firewall supports RFC 5425 encrypted syslog natively (for example, Cisco ASA, Palo Alto, or Fortinet devices with TLS syslog), you can send syslog directly to the relay over the internet using TLS on port 6514 — no tunnel required.

This is the simplest option if your device supports it, but it does expose the relay's TLS port to the internet. Mitigate this with:

- **IP allowlisting** — restrict port 6514 to your site's public IP in the NSG/Security Group.
- **Mutual TLS** — require the firewall to present a client certificate (see [docs/tls.md](tls.md)).

See [docs/tls.md](tls.md) for full TLS configuration instructions.

---

## Hosting options

### A — Docker on a cloud VM (recommended)

Running the relay on a Linux VM using Docker Compose is the closest to the standard on-premises deployment and gives you:

- Full control over networking and firewall rules.
- Automatic updates via the built-in update script (cron job).
- The same installation steps as on-premises — use the [one-line installer](../README.md#recommended-one-line-installer) or the provided [Docker Compose file](../installer/docker-compose.yaml).

**Azure:** Use an **Azure Virtual Machine** (Ubuntu 22.04 LTS or 24.04 LTS). A `Standard_B1ms` (1 vCPU, 2 GB RAM) is sufficient for most deployments.

**AWS:** Use an **EC2 instance** (Ubuntu, `t3.small` or larger). Attach a Security Group that restricts syslog ports to your site IP.

This is the recommended approach for production deployments because it supports automatic updates.

---

### B — Azure Container Instances (ACI)

ACI lets you run a single container without managing a VM. It is simpler to set up but has important limitations.

> **⚠ Automatic updates are not supported on ACI.**
> ACI runs a fixed container image — it does not watch for new image versions or pull updates automatically. To update the relay you must redeploy the container instance manually or via a CI/CD pipeline. If you use ACI, you are responsible for monitoring for new `stable` image releases and redeploying when they are available.

#### Minimal ACI deployment

```bash
# Create a resource group
az group create --name cyberalarm-rg --location uksouth

# Deploy the relay container
az container create \
  --resource-group cyberalarm-rg \
  --name syslog-relay \
  --image ghcr.io/waterstonsltd/cyberalarm-securesensor:stable \
  --os-type Linux \
  --cpu 1 --memory 2 \
  --ports 514 \
  --protocol TCP \
  --ip-address Public \
  --environment-variables \
      REGISTRATION_TOKEN=<your-token> \
      LOGGING__LOGLEVEL__DEFAULT=Information \
  --azure-file-volume-account-name <storage-account> \
  --azure-file-volume-account-key <storage-key> \
  --azure-file-volume-share-name syslog-relay-data \
  --azure-file-volume-mount-path /var/lib/syslog-relay
```

> **Note:** ACI does not support UDP port publishing via the Azure CLI's `--ports` flag. If you need UDP 514, deploy the container into a **Virtual Network** using an ACI subnet and route traffic via an Azure Load Balancer or Azure Firewall, or use TLS syslog on TCP 6514 instead.

#### Restricting access on ACI

ACI deployed with a public IP does not support Network Security Groups directly on the container. Use one of:

- **Virtual Network integration** — deploy the ACI into a VNet subnet and attach an NSG to that subnet.
- **Azure Firewall / Application Gateway** — place one in front of the ACI and restrict source IPs there.

#### Updating an ACI deployment

When a new `stable` image is published, delete and recreate the container instance:

```bash
az container delete --resource-group cyberalarm-rg --name syslog-relay --yes
az container create ... # same command as above
```

Or automate this with an Azure Logic App, Event Grid subscription on the container registry, or a scheduled pipeline.

---

### C — AWS Fargate (ECS)

AWS Fargate is the AWS equivalent of ACI — it runs containers without managing EC2 instances. The same automatic-update limitation applies.

> **⚠ Automatic updates are not supported on Fargate.**
> ECS task definitions reference a fixed image tag. To update, you must register a new task definition revision and force a service redeployment. Monitor for new `stable` releases and redeploy when they are available.

#### Minimal Fargate deployment (via AWS CLI)

Fargate requires a task definition, a cluster, and a service. The following is a condensed example — refer to [AWS ECS documentation](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/getting-started-fargate.html) for full details.

**1. Register a task definition** (`task-definition.json`):

```json
{
  "family": "syslog-relay",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "2048",
  "containerDefinitions": [
    {
      "name": "syslog-relay",
      "image": "ghcr.io/waterstonsltd/cyberalarm-securesensor:stable",
      "portMappings": [
        { "containerPort": 514, "protocol": "tcp" },
        { "containerPort": 514, "protocol": "udp" }
      ],
      "environment": [
        { "name": "REGISTRATION_TOKEN", "value": "<your-token>" }
      ],
      "mountPoints": [
        {
          "sourceVolume": "relay-data",
          "containerPath": "/var/lib/syslog-relay"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/syslog-relay",
          "awslogs-region": "eu-west-2",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ],
  "volumes": [
    {
      "name": "relay-data",
      "efsVolumeConfiguration": {
        "fileSystemId": "<efs-filesystem-id>",
        "rootDirectory": "/"
      }
    }
  ]
}
```

**2. Create and run the service:**

```bash
aws ecs register-task-definition --cli-input-json file://task-definition.json

aws ecs create-cluster --cluster-name cyberalarm

aws ecs create-service \
  --cluster cyberalarm \
  --service-name syslog-relay \
  --task-definition syslog-relay \
  --desired-count 1 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[<subnet-id>],securityGroups=[<sg-id>],assignPublicIp=ENABLED}"
```

> **Note on persistent storage:** Fargate tasks use ephemeral storage by default. The relay persists events to `/var/lib/syslog-relay` before upload. Use **Amazon EFS** mounted into the task (shown above) to preserve data across task restarts, or accept that any unpersisted events in the buffer will be lost if the task is stopped.

#### Restricting access on Fargate

Attach a Security Group to the Fargate task's network interface that allows inbound TCP/UDP 514 (and TCP 6514 for TLS) only from your site's public IP.

#### Updating a Fargate deployment

```bash
# Force a new deployment (pulls the latest digest for the :stable tag)
aws ecs update-service \
  --cluster cyberalarm \
  --service syslog-relay \
  --force-new-deployment
```

---

## Comparison summary

| | Docker on VM | Azure Container Instances | AWS Fargate |
|---|---|---|---|
| Automatic updates | ✅ Yes (built-in cron) | ❌ Manual redeploy | ❌ Manual redeploy |
| UDP syslog support | ✅ Full | ⚠ Requires VNet | ✅ Full (awsvpc) |
| NSG / Security Group on container | ✅ Via VM's NSG | ⚠ Requires VNet | ✅ Via Security Group |
| Persistent storage | ✅ Host volume | ✅ Azure Files | ⚠ Requires EFS |
| Operational complexity | Low | Low | Medium |
| Recommended for production | ✅ Yes | ⚠ With caveats | ⚠ With caveats |
