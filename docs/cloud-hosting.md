# Running the Syslog Relay in the Cloud

The relay is a standard Docker container, so it can run anywhere Docker runs — including cloud-hosted virtual machines and managed container services. This guide covers common cloud deployment patterns, how to securely bridge syslog from your on-premises network devices to a cloud-hosted relay, and what to consider when choosing a hosting approach.

---

## Securing syslog in transit

> **Syslog messages can contain sensitive information** — IP addresses, usernames, connection metadata, and security events from your network. **Never expose the syslog port directly to the public internet.**

In a cloud deployment the relay is not on the same LAN as your network devices, so you must choose one of two approaches to secure the traffic in transit:

| Approach | How it works |
|---|---|
| **VPN** | A site-to-site VPN (IPsec, IKEv2, or equivalent) between your on-premises firewall and the cloud network. Syslog travels over UDP/TCP 514 inside the encrypted tunnel — no relay changes needed. |
| **TLS syslog (RFC 5425)** | The firewall sends encrypted syslog natively over TCP 6514. Requires the relay to be configured for TLS and the port to be IP-restricted to your site. |

Neither approach is complete without also **restricting the syslog port to your site's IP address** at the network level. Use your cloud provider's controls to allow only your known source IPs:

- **Azure** — Network Security Group (NSG) inbound rule on port 514 (or 6514).
- **AWS** — Security Group inbound rule on port 514 (or 6514).

For the VPN approach, consult your firewall vendor's documentation and your cloud provider's VPN gateway documentation. The relay itself requires no configuration changes — once the tunnel is established, point your devices at the relay's private IP address as you would on-premises.

For TLS syslog, see [docs/tls.md](tls.md) for relay configuration, certificate requirements, and mutual TLS.

> **If you have a Linux server on-premises**, running the relay there is simpler — you get automatic updates, no cloud network configuration to maintain, and the standard installation applies. Consider cloud hosting when you have a specific operational reason (e.g. multiple sites, no suitable on-premises host, or a requirement for cloud-only infrastructure).

---

## Option 1 — TLS syslog

If your firewall supports RFC 5425 encrypted syslog natively (Cisco ASA, Palo Alto, Fortinet, and others), you can send syslog directly to the relay over the internet using TLS on port 6514 — no VPN required.

Restrict access with:

- **IP allowlisting** — limit port 6514 to your site's public IP in the NSG/Security Group.
- **Mutual TLS** — require the firewall to present a client certificate signed by your CA (see [docs/tls.md](tls.md)).

See [docs/tls.md](tls.md) for full configuration instructions.

---

## Option 2 — VPN

If your firewall supports a site-to-site VPN to a cloud gateway, syslog travels inside the encrypted tunnel exactly as it would on-premises. No changes to the relay are required — point your devices at the relay's private IP address.

Consult your firewall vendor's documentation and your cloud provider's VPN gateway documentation for setup. Once the tunnel is established, restrict port 514 in your NSG/Security Group to traffic from your on-premises subnet only.

---

## Hosting options

### Windows Server VM

If you cannot use Docker but still want a VM-based deployment, install the Windows release on a Windows Server VM and run it as a Windows service.

- Best fit: Windows Server 2019 or later on Azure VM or EC2
- Syslog ports: TCP/UDP 514 or TLS syslog on TCP 6514
- Updates: built in, fetched from promoted stable GitHub Releases
- Logs: `%ProgramData%\syslog-relay\logs\`

This avoids container runtime management, but it also means you lose the filesystem isolation and container-hardening defaults in the Docker deployment.

---

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
        Serilog__MinimumLevel__Default=Information \
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
