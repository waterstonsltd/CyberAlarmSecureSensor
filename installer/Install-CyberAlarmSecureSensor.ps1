#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs or reconfigures the CyberAlarm Secure Sensor Windows service.

.DESCRIPTION
    Downloads the latest MSI from GitHub, verifies its publisher signature,
    installs it machine-wide, writes the configuration file with the supplied
    registration token, and starts the Windows service.

.PARAMETER PreRelease
    When specified, the installer fetches the newest available release from GitHub
    (including pre-release builds) instead of using the API-approved stable version.
    Equivalent to switching a Docker deployment from :stable to :latest.
    Pre-release builds have not been validated for production use.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$RegistrationToken,

    [Parameter(Position = 1)]
    [ValidateSet('prod', 'dev', 'uat')]
    [string]$Environment = 'prod',

    [Parameter()]
    [switch]$SkipPublisherVerification,

    # Install the latest pre-release build rather than the API-approved stable version.
    # Pre-release builds are not validated for production use.
    [Parameter()]
    [switch]$PreRelease
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

function Get-LatestPreReleaseVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GitHubRepo
    )

    $apiUrl = "https://api.github.com/repos/$GitHubRepo/releases"

    try {
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add('User-Agent', 'CyberAlarm-Installer')
        $webClient.Headers.Add('Accept', 'application/vnd.github+json')
        $releasesJson = $webClient.DownloadString($apiUrl)
    }
    catch {
        throw "Failed to fetch releases from GitHub API ($apiUrl). $($_.Exception.Message)"
    }

    try {
        $releases = $releasesJson | ConvertFrom-Json
    }
    catch {
        throw "Failed to parse GitHub releases response. $($_.Exception.Message)"
    }

    # Find the newest release (pre-release or stable) by published date
    $latest = $releases |
        Where-Object { -not $_.draft } |
        Sort-Object { [datetime]$_.published_at } -Descending |
        Select-Object -First 1

    if (-not $latest) {
        throw 'No published releases found in the GitHub repository.'
    }

    $tag = $latest.tag_name -replace '^v', ''

    try {
        $version = [Version]$tag
    }
    catch {
        throw "Latest GitHub release tag '$($latest.tag_name)' is not a valid version number."
    }

    if ($latest.prerelease) {
        Write-Warning "Installing pre-release build $($latest.tag_name) (-PreRelease was specified). This build has not been validated for production use."
    }

    return $version.ToString()
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

    if ($approvedVersion -le [Version]'0.0.0') {
        throw "Relay status currentVersion '$($status.CurrentVersion)' does not point to an approved stable Windows release yet."
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

function Get-ObjectPropertyValue {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName
    )

    $property = $InputObject.PSObject.Properties[$PropertyName]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function Get-InstalledDeploymentTool {
    $uninstallRoots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $candidates = foreach ($root in $uninstallRoots) {
        Get-ItemProperty -Path $root -ErrorAction SilentlyContinue |
            Where-Object { (Get-ObjectPropertyValue -InputObject $_ -PropertyName 'DisplayName') -eq 'CyberAlarm Secure Sensor Deployment Tool' }
    }

    $installed = $candidates |
        Sort-Object {
            $displayVersion = Get-ObjectPropertyValue -InputObject $_ -PropertyName 'DisplayVersion'
            if ($displayVersion) {
                try { [Version]$displayVersion } catch { [Version]'0.0.0.0' }
            }
            else {
                [Version]'0.0.0.0'
            }
        } -Descending |
        Select-Object -First 1

    if (-not $installed) {
        return $null
    }

    $parsedVersion = $null
    $displayVersion = Get-ObjectPropertyValue -InputObject $installed -PropertyName 'DisplayVersion'
    if ($displayVersion) {
        try {
            $parsedVersion = [Version]$displayVersion
        }
        catch {
            $parsedVersion = $null
        }
    }

    [pscustomobject]@{
        DisplayName = Get-ObjectPropertyValue -InputObject $installed -PropertyName 'DisplayName'
        DisplayVersion = $displayVersion
        Version = $parsedVersion
        ProductCode = Get-ObjectPropertyValue -InputObject $installed -PropertyName 'PSChildName'
        UninstallString = Get-ObjectPropertyValue -InputObject $installed -PropertyName 'UninstallString'
        InstallLocation = Get-ObjectPropertyValue -InputObject $installed -PropertyName 'InstallLocation'
    }
}

function Get-UninstallCommandText {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProductCode,

        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )

    return "Start-Process -FilePath `"$env:SystemRoot\System32\msiexec.exe`" -Wait -Verb RunAs -ArgumentList '/x','$ProductCode','/qn','/norestart','/l*v','$LogPath'"
}

function Resolve-DeploymentToolExecutablePath {
    param(
        [psobject]$InstalledDeploymentTool
    )

    $candidatePaths = @()

    $installLocation = $null
    if ($InstalledDeploymentTool) {
        $installLocation = Get-ObjectPropertyValue -InputObject $InstalledDeploymentTool -PropertyName 'InstallLocation'
    }

    if ($installLocation) {
        $candidatePaths += Join-Path $installLocation 'CyberAlarmSecureSensorDeploymentTool.exe'
    }

    $programFilesX86 = [Environment]::GetFolderPath('ProgramFilesX86')
    if ($programFilesX86) {
        $candidatePaths += Join-Path $programFilesX86 'CyberAlarm Secure Sensor Deployment Tool\CyberAlarmSecureSensorDeploymentTool.exe'
    }

    foreach ($candidatePath in $candidatePaths | Select-Object -Unique) {
        if (Test-Path $candidatePath) {
            return $candidatePath
        }
    }

    return $null
}

function Invoke-DeploymentToolInstall {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExecutablePath,

        [Parameter(Mandatory = $true)]
        [string]$InstallTo
    )

    Write-Host "Finalizing Windows service installation to $InstallTo ..."
    $process = Start-Process -FilePath $ExecutablePath -ArgumentList "--installto `"$InstallTo`"" -Wait -NoNewWindow -PassThru
    if ($process.ExitCode -ne 0) {
        throw "Deployment Tool installation failed with exit code $($process.ExitCode)."
    }
}

$ServiceName   = "CyberAlarm Syslog Relay"
$VelopackInstallDir = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'CyberAlarmSecureSensor'
$ConfigDir     = "C:\ProgramData\syslog-relay"
$ConfigPath    = Join-Path $ConfigDir "appsettings.windows.local.json"
$InstallerLogDir = Join-Path $ConfigDir "installer-logs"
$GitHubRepo    = 'waterstonsltd/CyberAlarmSecureSensor'
$ExpectedPublisher = 'Waterstons'
$MsiFileName   = "CyberAlarmSecureSensor-win-DeploymentTool.msi"
$DownloadDir   = Join-Path $env:TEMP 'CyberAlarmSecureSensorInstaller'
$MsiPath       = Join-Path $DownloadDir $MsiFileName
$resolvedApiBaseUrl = Resolve-ApiBaseUrl -SelectedEnvironment $Environment
$shouldRunDeploymentToolInstallCheck = $false

Assert-RegistrationToken -Token $RegistrationToken
New-Item -ItemType Directory -Path $InstallerLogDir -Force | Out-Null

# PowerShell 5.1 defaults to TLS 1.0; GitHub requires TLS 1.2.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ---------------------------------------------------------------------------
# Download and install MSI (skip if already installed and service exists)
# ---------------------------------------------------------------------------
$serviceExists = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
$installedDeploymentTool = Get-InstalledDeploymentTool

if (-not $serviceExists -and -not $installedDeploymentTool) {
    if ($PreRelease) {
        $approvedVersion = Get-LatestPreReleaseVersion -GitHubRepo $GitHubRepo
    }
    else {
        $approvedVersion = Get-ApprovedReleaseVersion -ApiBaseUrl $resolvedApiBaseUrl
    }
    $ReleaseBaseUrl = "https://github.com/$GitHubRepo/releases/download/v$approvedVersion"
    $MsiUrl = "$ReleaseBaseUrl/$MsiFileName"

    New-Item -ItemType Directory -Path $DownloadDir -Force | Out-Null

    Write-Host "Downloading CyberAlarm Secure Sensor version $approvedVersion..."
    (New-Object System.Net.WebClient).DownloadFile($MsiUrl, $MsiPath)

    if ($SkipPublisherVerification) {
        Write-Warning 'Skipping MSI publisher signature verification because -SkipPublisherVerification was specified.'
    }
    else {
        Write-Host "Verifying MSI publisher signature..."
        Assert-AuthenticodePublisher -Path $MsiPath -PublisherName $ExpectedPublisher
    }

    Write-Host "Installing (this may take a moment)..."
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $MsiLog = Join-Path $InstallerLogDir "CyberAlarmSecureSensor-install-$timestamp.log"
    $msi = Start-Process msiexec -ArgumentList "/i `"$MsiPath`" /quiet /norestart /l*v `"$MsiLog`"" -Wait -NoNewWindow -PassThru
    if ($msi.ExitCode -notin 0, 3010) {
        Write-Host ""
        Write-Host "MSI log: $MsiLog" -ForegroundColor Yellow
        Write-Host "MSI retained at: $MsiPath" -ForegroundColor Yellow
        if (Test-Path $MsiLog) {
            Write-Host "--- MSI failure lines (Return value 3 / Error / CustomAction) ---" -ForegroundColor Yellow
            $logLines = Get-Content $MsiLog
            $errorLines = $logLines | Where-Object { $_ -match 'Return value 3|Error\b|CustomAction.*returned actual error|CAQuietExec|failed|exception' }
            if ($errorLines) {
                $errorLines | Write-Host
            } else {
                Write-Host "(No error pattern matched - dumping last 60 lines)" -ForegroundColor Yellow
                $logLines | Select-Object -Last 60 | Write-Host
            }
        }
        Write-Error "MSI installation failed with exit code $($msi.ExitCode). See log above for details."
    }

    Remove-Item $MsiPath -Force -ErrorAction SilentlyContinue
    Write-Host "Installation complete."
    $shouldRunDeploymentToolInstallCheck = $true
} elseif ($installedDeploymentTool) {
    $installedVersionText = if ($installedDeploymentTool.DisplayVersion) { $installedDeploymentTool.DisplayVersion } else { 'unknown' }
    Write-Host "Deployment Tool is already installed (version $installedVersionText) - skipping MSI installation."

    if (-not $serviceExists) {
        Write-Warning "The Deployment Tool is installed but the '$ServiceName' service was not found."
        Write-Host "Attempting to finalize the existing Deployment Tool installation..."
        $shouldRunDeploymentToolInstallCheck = $true
    }
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
        AllowPreRelease    = [bool]$PreRelease
    }
} | ConvertTo-Json -Depth 3

[System.IO.File]::WriteAllText($ConfigPath, $config, [System.Text.UTF8Encoding]::new($false))

if ($shouldRunDeploymentToolInstallCheck) {
    $installedDeploymentTool = Get-InstalledDeploymentTool
    $deploymentToolExecutablePath = Resolve-DeploymentToolExecutablePath -InstalledDeploymentTool $installedDeploymentTool

    if (-not $deploymentToolExecutablePath) {
        $uninstallLogPath = Join-Path $InstallerLogDir 'CyberAlarmSecureSensor-uninstall.log'
        Write-Warning 'The Deployment Tool executable could not be found after installation.'
        if ($installedDeploymentTool -and $installedDeploymentTool.ProductCode) {
            $uninstallCommand = Get-UninstallCommandText -ProductCode $installedDeploymentTool.ProductCode -LogPath $uninstallLogPath
            Write-Host 'Suggested uninstall command:' -ForegroundColor Yellow
            Write-Host "  $uninstallCommand" -ForegroundColor Yellow
        }

        throw 'Deployment Tool executable was not found, so the Windows service could not be finalized.'
    }

    Invoke-DeploymentToolInstall -ExecutablePath $deploymentToolExecutablePath -InstallTo $VelopackInstallDir
}

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

# ---------------------------------------------------------------------------
# Windows Firewall rules
# ---------------------------------------------------------------------------
$firewallRuleName = "CyberAlarm Secure Sensor - Syslog"
Write-Host "Configuring Windows Firewall rules for syslog (TCP/UDP port 514)..."
foreach ($protocol in @('TCP', 'UDP')) {
    $ruleName = "$firewallRuleName ($protocol)"
    $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "  Firewall rule '$ruleName' already exists - skipping."
    } else {
        New-NetFirewallRule `
            -DisplayName $ruleName `
            -Direction Inbound `
            -Action Allow `
            -Protocol $protocol `
            -LocalPort 514 `
            -Profile Any `
            -Description "Allow inbound syslog traffic to CyberAlarm Secure Sensor" | Out-Null
        Write-Host "  Created firewall rule '$ruleName'."
    }
}

# ---------------------------------------------------------------------------
# Power management advisory
# ---------------------------------------------------------------------------
function Get-AcSleepTimeoutSeconds {
    $output = powercfg /query SCHEME_CURRENT SUB_SLEEP STANDBYIDLE 2>$null
    if (-not $output) { return $null }
    $line = $output | Where-Object { $_ -match 'Current AC Power Setting Index' }
    if (-not $line) { return $null }
    $hexStr = (($line | Select-Object -First 1) -split ':')[-1].Trim()
    try { return [Convert]::ToUInt32($hexStr, 16) } catch { return $null }
}

$osProductType = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType
$isWorkstationOs = $osProductType -eq 1  # 1 = Workstation; 2 = Domain Controller; 3 = Server
$acSleepSeconds = Get-AcSleepTimeoutSeconds
$sleepIsEnabled  = ($null -ne $acSleepSeconds) -and ($acSleepSeconds -gt 0)

if ($isWorkstationOs -or $sleepIsEnabled) {
    $reasons = @()
    if ($isWorkstationOs) {
        $reasons += 'this machine is running a desktop/workstation edition of Windows'
    }
    if ($sleepIsEnabled) {
        $sleepMinutes = [Math]::Round($acSleepSeconds / 60)
        $reasons += "the active power plan allows the machine to sleep after $sleepMinutes minute(s) on AC power"
    }
    Write-Warning (
        'Power management advisory: ' + ($reasons -join ' and ') + '. ' +
        'If this machine sleeps, the relay will stop receiving syslog events and any data sent during that period will be lost. ' +
        "To prevent this, open Power Options and set 'Put the computer to sleep' to 'Never' (plugged in), " +
        'or deploy the relay on a server or a dedicated always-on host.'
    )
}
