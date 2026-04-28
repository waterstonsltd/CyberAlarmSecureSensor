#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs or reconfigures the CyberAlarm Secure Sensor Windows service.

.DESCRIPTION
    Downloads the latest MSI from GitHub, installs it machine-wide, writes
    the configuration file with the supplied registration token, and starts
    the Windows service.

    This script is generated server-side. The API replaces the placeholders
    below based on the environment it is running in before serving the script
    to the end user.

.PLACEHOLDER REPLACEMENTS
    {{REGISTRATION_TOKEN}}  - The customer-specific registration token
#>

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Configuration — REGISTRATION_TOKEN is replaced server-side before delivery.
# All other values are set by the API based on its own environment.
# ---------------------------------------------------------------------------
$Token         = "{{REGISTRATION_TOKEN}}"
$ApiBaseUrl    = "{{API_BASE_URL}}"
$GitHubRepo    = "{{GITHUB_REPO}}"
# ---------------------------------------------------------------------------

$ServiceName   = "CyberAlarm Syslog Relay"
$ConfigDir     = "C:\ProgramData\syslog-relay"
$ConfigPath    = Join-Path $ConfigDir "appsettings.windows.local.json"
$MsiFileName   = "CyberAlarmSecureSensor-win-DeploymentTool.msi"
$MsiUrl        = "https://github.com/$GitHubRepo/releases/latest/download/$MsiFileName"
$MsiPath       = Join-Path $env:TEMP $MsiFileName

# ---------------------------------------------------------------------------
# Validate placeholders were replaced
# ---------------------------------------------------------------------------
foreach ($pair in @(
    @{ Name = 'REGISTRATION_TOKEN'; Value = $Token }
)) {
    if ($pair.Value -like '{{*}}') {
        Write-Error "Placeholder $($pair.Name) was not replaced before running this script."
    }
}

# ---------------------------------------------------------------------------
# Download and install MSI (skip if already installed and service exists)
# ---------------------------------------------------------------------------
$serviceExists = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

if (-not $serviceExists) {
    Write-Host "Downloading CyberAlarm Secure Sensor..."
    Invoke-WebRequest -Uri $MsiUrl -OutFile $MsiPath -UseBasicParsing

    Write-Host "Installing (this may take a moment)..."
    $msi = Start-Process msiexec -ArgumentList "/i `"$MsiPath`" /quiet /norestart" -Wait -NoNewWindow -PassThru
    if ($msi.ExitCode -notin 0, 3010) {
        Write-Error "MSI installation failed with exit code $($msi.ExitCode)."
    }

    Remove-Item $MsiPath -Force -ErrorAction SilentlyContinue
    Write-Host "Installation complete."
} else {
    Write-Host "Service already installed — updating configuration only."
}

# ---------------------------------------------------------------------------
# Write configuration
# ---------------------------------------------------------------------------
Write-Host "Writing configuration to $ConfigPath..."

New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $ConfigDir "logs") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $ConfigDir "drop") -Force | Out-Null

$config = [ordered]@{
    REGISTRATION_TOKEN  = $Token
    ApiBaseUrl          = $ApiBaseUrl
    FileWatcherEnabled  = $false
    FileWatcherDropPath = "C:\ProgramData\syslog-relay\drop"
    WindowsUpdate       = [ordered]@{
        Enabled            = $true
        CheckIntervalHours = 4
        RepositoryUrl      = "https://github.com/$GitHubRepo"
    }
} | ConvertTo-Json -Depth 3

[System.IO.File]::WriteAllText($ConfigPath, $config, [System.Text.UTF8Encoding]::new($false))

# ---------------------------------------------------------------------------
# Start / restart service
# ---------------------------------------------------------------------------
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "Restarting service..."
    Restart-Service -Name $ServiceName -Force
    Write-Host "CyberAlarm Secure Sensor is running."
} else {
    Write-Warning "Service '$ServiceName' was not found after install. Check Windows Event Log for details."
}
