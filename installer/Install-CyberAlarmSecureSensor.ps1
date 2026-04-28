#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs or reconfigures the CyberAlarm Secure Sensor Windows service.

.DESCRIPTION
    Downloads the latest MSI from GitHub, verifies its publisher signature,
    installs it machine-wide, writes the configuration file with the supplied
    registration token, and starts the Windows service.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$RegistrationToken,

    [Parameter(Position = 1)]
    [ValidateSet('prod', 'dev', 'uat')]
    [string]$Environment = 'prod'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-RegistrationToken {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token
    )

    if ([string]::IsNullOrWhiteSpace($Token)) {
        throw 'Registration token is required.'
    }

    if ($Token -match '\s') {
        throw 'Registration token must not contain whitespace.'
    }
}

function Resolve-ApiBaseUrl {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SelectedEnvironment
    )

    switch ($SelectedEnvironment) {
        'dev' { return 'https://dev-api.cyberalarm.police.uk' }
        'uat' { return 'https://uat-api.cyberalarm.police.uk' }
        default { return 'https://api.cyberalarm.police.uk' }
    }
}

function Get-ApprovedReleaseVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiBaseUrl
    )

    $statusUrl = "$ApiBaseUrl/api/v1/SyslogRelayStatus"

    try {
        $statusResponse = (New-Object System.Net.WebClient).DownloadString($statusUrl)
    }
    catch {
        throw "Failed to fetch relay status from $statusUrl. $($_.Exception.Message)"
    }

    try {
        $status = $statusResponse | ConvertFrom-Json
    }
    catch {
        throw "Failed to parse relay status response from $statusUrl. $($_.Exception.Message)"
    }

    if ([string]::IsNullOrWhiteSpace($status.CurrentVersion)) {
        throw "Relay status response from $statusUrl did not include currentVersion."
    }

    try {
        $approvedVersion = [Version]$status.CurrentVersion
    }
    catch {
        throw "Relay status currentVersion '$($status.CurrentVersion)' is invalid."
    }

    return $approvedVersion.ToString()
}

function Assert-AuthenticodePublisher {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$PublisherName
    )

    $signature = Get-AuthenticodeSignature -FilePath $Path
    if ($signature.Status -ne 'Valid') {
        throw "Installer signature is not valid: $($signature.Status)"
    }

    if (-not $signature.SignerCertificate) {
        throw 'Installer is not signed.'
    }

    if ($signature.SignerCertificate.Subject -notmatch [Regex]::Escape($PublisherName)) {
        throw "Installer signer was not the expected publisher. Subject: $($signature.SignerCertificate.Subject)"
    }

    if (-not $signature.TimeStamperCertificate) {
        throw 'Installer signature is missing a timestamp.'
    }
}

$ServiceName   = "CyberAlarm Syslog Relay"
$ConfigDir     = "C:\ProgramData\syslog-relay"
$ConfigPath    = Join-Path $ConfigDir "appsettings.windows.local.json"
$GitHubRepo    = 'waterstonsltd/CyberAlarmSecureSensor'
$ExpectedPublisher = 'Waterstons'
$MsiFileName   = "CyberAlarmSecureSensor-win-DeploymentTool.msi"
$DownloadDir   = Join-Path $env:TEMP 'CyberAlarmSecureSensorInstaller'
$MsiPath       = Join-Path $DownloadDir $MsiFileName
$resolvedApiBaseUrl = Resolve-ApiBaseUrl -SelectedEnvironment $Environment

Assert-RegistrationToken -Token $RegistrationToken

# PowerShell 5.1 defaults to TLS 1.0; GitHub requires TLS 1.2.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ---------------------------------------------------------------------------
# Download and install MSI (skip if already installed and service exists)
# ---------------------------------------------------------------------------
$serviceExists = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

if (-not $serviceExists) {
    $approvedVersion = Get-ApprovedReleaseVersion -ApiBaseUrl $resolvedApiBaseUrl
    $ReleaseBaseUrl = "https://github.com/$GitHubRepo/releases/download/v$approvedVersion"
    $MsiUrl = "$ReleaseBaseUrl/$MsiFileName"

    New-Item -ItemType Directory -Path $DownloadDir -Force | Out-Null

    Write-Host "Downloading CyberAlarm Secure Sensor version $approvedVersion..."
    (New-Object System.Net.WebClient).DownloadFile($MsiUrl, $MsiPath)

    Write-Host "Verifying MSI publisher signature..."
    Assert-AuthenticodePublisher -Path $MsiPath -PublisherName $ExpectedPublisher

    Write-Host "Installing (this may take a moment)..."
    $msi = Start-Process msiexec -ArgumentList "/i `"$MsiPath`" /quiet /norestart" -Wait -NoNewWindow -PassThru
    if ($msi.ExitCode -notin 0, 3010) {
        Write-Error "MSI installation failed with exit code $($msi.ExitCode)."
    }

    Remove-Item $MsiPath -Force -ErrorAction SilentlyContinue
    Write-Host "Installation complete."
} else {
    Write-Host "Service already installed - updating configuration only."
}

# ---------------------------------------------------------------------------
# Write configuration
# ---------------------------------------------------------------------------
Write-Host "Writing configuration to $ConfigPath..."

New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $ConfigDir "logs") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $ConfigDir "drop") -Force | Out-Null

$config = [ordered]@{
    REGISTRATION_TOKEN  = $RegistrationToken
    ApiBaseUrl          = $resolvedApiBaseUrl
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
    if ($svc.Status -eq 'Running') {
        Write-Host "Restarting service..."
        Restart-Service -Name $ServiceName -Force
    }
    else {
        Write-Host "Starting service..."
        Start-Service -Name $ServiceName
    }

    Write-Host "CyberAlarm Secure Sensor is running."
} else {
    Write-Warning "Service '$ServiceName' was not found after install. Check Windows Event Log for details."
}
