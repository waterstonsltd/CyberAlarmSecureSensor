#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs or reconfigures the CyberAlarm Secure Sensor Windows service.

.DESCRIPTION
    Downloads the latest MSI bootstrap package from GitHub, verifies its
    publisher signature, installs it machine-wide, writes the configuration
    file with the supplied registration token, and starts the Windows service.

.PARAMETER Reinstall
    Re-registers the Windows service and rewrites the configuration file using
    the token and environment already present on this machine. Use this to
    recover a broken or missing service registration without needing to supply
    the registration token again. Requires an existing configuration file at
    %ProgramData%\syslog-relay\appsettings.windows.local.json.

.PARAMETER Uninstall
    Removes the installed CyberAlarm Secure Sensor Windows installation. For
    legacy installs created by the older Deployment Tool MSI wrapper, the script
    also removes that wrapper when it is present.

.PARAMETER PreRelease
    When specified, the installer fetches the newest available release from GitHub
    (including pre-release builds) instead of using the API-approved stable version.
    Equivalent to switching a Docker deployment from :stable to :latest.
    Pre-release builds have not been validated for production use.
#>

[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
    [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Install')]
    [string]$RegistrationToken,

    [Parameter(Position = 1, ParameterSetName = 'Install')]
    [Parameter(Position = 0, ParameterSetName = 'Uninstall')]
    [ValidateSet('prod', 'dev', 'uat')]
    [string]$Environment = 'prod',

    [Parameter(ParameterSetName = 'Install')]
    [switch]$SkipPublisherVerification,

    # Install the latest pre-release build rather than the API-approved stable version.
    # Pre-release builds are not validated for production use.
    [Parameter(ParameterSetName = 'Install')]
    [switch]$PreRelease,

    [Parameter(Mandatory = $true, ParameterSetName = 'Reinstall')]
    [switch]$Reinstall,

    [Parameter(Mandatory = $true, ParameterSetName = 'Uninstall')]
    [switch]$Uninstall
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
        'dev'   { return 'https://dev-api.cyberalarm.police.uk' }
        'uat'   { return 'https://uat-api.cyberalarm.police.uk' }
        default { return 'https://api.cyberalarm.police.uk' }
    }
}

function Invoke-FileDownload {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [string]$OutFile,

        [int]$TimeoutSeconds = 120,

        # 200 MB - well above any expected MSI size; guards against runaway responses
        [long]$MaxBytes = 200MB
    )

    Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing -TimeoutSec $TimeoutSeconds

    $fileSize = (Get-Item $OutFile).Length
    if ($fileSize -gt $MaxBytes) {
        Remove-Item $OutFile -Force -ErrorAction SilentlyContinue
        throw "Downloaded file size ($([Math]::Round($fileSize / 1MB, 1)) MB) exceeds the maximum expected size ($([Math]::Round($MaxBytes / 1MB)) MB). Aborting."
    }
}

function Get-LatestPreReleaseVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GitHubRepo
    )

    $apiUrl = "https://api.github.com/repos/$GitHubRepo/releases"

    try {
        $releases = Invoke-RestMethod -Uri $apiUrl -TimeoutSec 30 -Headers @{
            'User-Agent' = 'CyberAlarm-Installer'
            'Accept'     = 'application/vnd.github+json'
        }
    }
    catch {
        throw "Failed to fetch releases from GitHub API ($apiUrl). $($_.Exception.Message)"
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
        $status = Invoke-RestMethod -Uri $statusUrl -TimeoutSec 30
    }
    catch {
        throw "Failed to fetch relay status from $statusUrl. $($_.Exception.Message)"
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
        [string]$ExpectedCN
    )

    $signature = Get-AuthenticodeSignature -FilePath $Path

    if ($signature.Status -ne 'Valid') {
        $detail = switch ($signature.Status) {
            'NotSigned'    { 'The file is not signed.' }
            'HashMismatch' { 'The file hash does not match the signature - the file may have been tampered with.' }
            'NotTrusted'   { 'The signing certificate chain is not trusted on this machine.' }
            'UnknownError' { 'An unknown signature error occurred.' }
            default        { "Signature status: $($signature.Status)" }
        }
        throw "Installer signature verification failed. $detail"
    }

    if (-not $signature.SignerCertificate) {
        throw 'Installer has no signer certificate.'
    }

    # Extract CN from the Subject distinguished name
    $subject = $signature.SignerCertificate.Subject
    $cnMatch = [Regex]::Match($subject, '(?:^|,\s*)CN=([^,]+)')
    if (-not $cnMatch.Success) {
        throw "Could not extract CN from certificate Subject: $subject"
    }

    $cn = $cnMatch.Groups[1].Value.Trim()
    if ($cn -ne $ExpectedCN) {
        throw "Installer publisher CN '$cn' does not match expected '$ExpectedCN'. Full subject: $subject"
    }

    if (-not $signature.TimeStamperCertificate) {
        throw 'Installer signature is missing a countersignature timestamp. The signature cannot be verified after certificate expiry.'
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
        DisplayName    = Get-ObjectPropertyValue -InputObject $installed -PropertyName 'DisplayName'
        DisplayVersion = $displayVersion
        Version        = $parsedVersion
        ProductCode    = Get-ObjectPropertyValue -InputObject $installed -PropertyName 'PSChildName'
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

function Get-ServiceExecutablePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
    if (-not $service -or [string]::IsNullOrWhiteSpace($service.PathName)) {
        return $null
    }

    $pathName = $service.PathName.Trim()
    if ($pathName.StartsWith('"')) {
        $closingQuoteIndex = $pathName.IndexOf('"', 1)
        if ($closingQuoteIndex -gt 1) {
            return $pathName.Substring(1, $closingQuoteIndex - 1)
        }
    }

    return ($pathName -split '\s+')[0]
}

function Get-InstalledSensor {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName
    )

    $serviceExePath = Get-ServiceExecutablePath -Name $ServiceName
    if (-not $serviceExePath -or -not (Test-Path $serviceExePath)) {
        return $null
    }

    $displayVersion = (Get-Item $serviceExePath).VersionInfo.FileVersion
    $parsedVersion = $null
    if ($displayVersion) {
        try {
            $parsedVersion = [Version]$displayVersion
        }
        catch {
            $parsedVersion = $null
        }
    }

    [pscustomobject]@{
        DisplayVersion = $displayVersion
        Version        = $parsedVersion
        ExecutablePath = $serviceExePath
    }
}

function Resolve-SensorUpdaterPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,

        [Parameter(Mandatory = $true)]
        [string]$DefaultInstallRoot
    )

    $candidatePaths = @(
        (Join-Path $DefaultInstallRoot 'Update.exe')
    )

    $serviceExePath = Get-ServiceExecutablePath -Name $ServiceName
    if ($serviceExePath) {
        $serviceCurrentDir = Split-Path $serviceExePath -Parent
        if ($serviceCurrentDir) {
            $serviceRootDir = Split-Path $serviceCurrentDir -Parent
            if ($serviceRootDir) {
                $candidatePaths += Join-Path $serviceRootDir 'Update.exe'
            }
        }
    }

    foreach ($candidatePath in $candidatePaths | Select-Object -Unique) {
        if ($candidatePath -and (Test-Path $candidatePath)) {
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

    Write-Output "Finalizing Windows service installation to $InstallTo ..."
    $process = Start-Process -FilePath $ExecutablePath -ArgumentList "--silent --installto `"$InstallTo`"" -Wait -NoNewWindow -PassThru
    if ($process.ExitCode -ne 0) {
        throw "Deployment Tool installation failed with exit code $($process.ExitCode)."
    }
}

function Invoke-SensorUninstall {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UpdaterPath
    )

    Write-Output 'Uninstalling CyberAlarm Secure Sensor ...'
    $process = Start-Process -FilePath $UpdaterPath -ArgumentList '--uninstall --silent' -Wait -NoNewWindow -PassThru
    if ($process.ExitCode -ne 0) {
        throw "Sensor uninstall failed with exit code $($process.ExitCode)."
    }
}

function Invoke-DeploymentToolUninstall {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProductCode,

        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )

    Write-Output 'Uninstalling CyberAlarm Secure Sensor Deployment Tool ...'
    $process = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" -ArgumentList "/x $ProductCode /qn /norestart /l*v `"$LogPath`"" -Wait -NoNewWindow -PassThru
    if ($process.ExitCode -notin 0, 3010) {
        throw "Deployment Tool MSI uninstall failed with exit code $($process.ExitCode). See $LogPath for details."
    }
}

function Invoke-BootstrapMsiUninstall {
    param(
        [Parameter(Mandatory = $true)]
        [string]$MsiPath,

        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )

    Write-Output 'Uninstalling CyberAlarm Secure Sensor MSI package ...'
    $process = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" -ArgumentList "/x `"$MsiPath`" /qn /norestart /l*v `"$LogPath`"" -Wait -NoNewWindow -PassThru
    if ($process.ExitCode -notin 0, 3010) {
        throw "Sensor MSI uninstall failed with exit code $($process.ExitCode). See $LogPath for details."
    }
}

$ServiceName        = "CyberAlarm Syslog Relay"
$VelopackInstallDir = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'CyberAlarmSecureSensor'
$ConfigDir          = "C:\ProgramData\syslog-relay"
$ConfigPath         = Join-Path $ConfigDir "appsettings.windows.local.json"
$InstallerLogDir    = Join-Path $ConfigDir "installer-logs"
$GitHubRepo         = 'waterstonsltd/CyberAlarmSecureSensor'
$ExpectedPublisher  = 'Waterstons Limited'
$MsiFileName        = "CyberAlarmSecureSensor-stable.msi"
$DownloadDir        = Join-Path $env:TEMP 'CyberAlarmSecureSensorInstaller'
$MsiPath            = Join-Path $DownloadDir $MsiFileName
$resolvedApiBaseUrl = Resolve-ApiBaseUrl -SelectedEnvironment $Environment
$shouldRunDeploymentToolInstallCheck = $false

New-Item -ItemType Directory -Path $InstallerLogDir -Force | Out-Null

# Older Windows PowerShell hosts can default to TLS 1.0/1.1, which GitHub rejects.
# Preserve the host policy and add TLS 1.2 only when it is not already enabled.
$currentSecurityProtocol = [Net.ServicePointManager]::SecurityProtocol
if (($currentSecurityProtocol -band [Net.SecurityProtocolType]::Tls12) -eq 0) {
    [Net.ServicePointManager]::SecurityProtocol = $currentSecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}

$installedDeploymentTool = Get-InstalledDeploymentTool
$installedSensor = Get-InstalledSensor -ServiceName $ServiceName

if ($Uninstall) {
    if ($installedDeploymentTool -and $installedDeploymentTool.ProductCode) {
        $sensorUpdaterPath = Resolve-SensorUpdaterPath -ServiceName $ServiceName -DefaultInstallRoot $VelopackInstallDir
        if ($sensorUpdaterPath) {
            Invoke-SensorUninstall -UpdaterPath $sensorUpdaterPath
        }
        else {
            Write-Warning 'The sensor updater executable was not found, so the installed sensor application could not be uninstalled automatically.'
        }

        $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $msiLog = Join-Path $InstallerLogDir "CyberAlarmSecureSensor-uninstall-$timestamp.log"
        Invoke-DeploymentToolUninstall -ProductCode $installedDeploymentTool.ProductCode -LogPath $msiLog
    }
    elseif ($installedSensor -and $installedSensor.Version) {
        $installedVersion = $installedSensor.Version.ToString()
        $releaseBaseUrl = "https://github.com/$GitHubRepo/releases/download/v$installedVersion"
        $msiUrl = "$releaseBaseUrl/$MsiFileName"
        $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $msiLog = Join-Path $InstallerLogDir "CyberAlarmSecureSensor-uninstall-$timestamp.log"

        New-Item -ItemType Directory -Path $DownloadDir -Force | Out-Null
        try {
            Write-Output "Downloading CyberAlarm Secure Sensor MSI $installedVersion for uninstall..."
            Invoke-FileDownload -Uri $msiUrl -OutFile $MsiPath
            Assert-AuthenticodePublisher -Path $MsiPath -ExpectedCN $ExpectedPublisher
            Invoke-BootstrapMsiUninstall -MsiPath $MsiPath -LogPath $msiLog
        }
        finally {
            Remove-Item $DownloadDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    else {
        Write-Warning 'No installed CyberAlarm Secure Sensor MSI package was detected, so only a best-effort application uninstall was possible.'

        $sensorUpdaterPath = Resolve-SensorUpdaterPath -ServiceName $ServiceName -DefaultInstallRoot $VelopackInstallDir
        if ($sensorUpdaterPath) {
            Invoke-SensorUninstall -UpdaterPath $sensorUpdaterPath
        }
        else {
            Write-Warning 'The sensor updater executable was not found, so the installed sensor application could not be uninstalled automatically.'
        }
    }

    Write-Output 'CyberAlarm Secure Sensor uninstall completed.'
    return
}

if ($Reinstall) {
    if (-not (Test-Path $ConfigPath)) {
        throw "No existing configuration found at '$ConfigPath'. Cannot reinstall without a token - run the installer with -RegistrationToken instead."
    }

    $existingConfig = Get-Content $ConfigPath -Raw | ConvertFrom-Json
    $RegistrationToken = $existingConfig.REGISTRATION_TOKEN

    if ([string]::IsNullOrWhiteSpace($RegistrationToken)) {
        throw "Registration token not found in existing configuration at '$ConfigPath'. Run the installer with -RegistrationToken instead."
    }

    if (-not [string]::IsNullOrWhiteSpace($existingConfig.ApiBaseUrl)) {
        $resolvedApiBaseUrl = $existingConfig.ApiBaseUrl
    }

    Write-Output "Reinstalling using existing configuration (token and environment preserved from $ConfigPath)."
}

Assert-RegistrationToken -Token $RegistrationToken

# ---------------------------------------------------------------------------
# Download and install MSI (skip if already installed and up to date)
# ---------------------------------------------------------------------------
$serviceExists = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

if ($PreRelease) {
    $approvedVersion = Get-LatestPreReleaseVersion -GitHubRepo $GitHubRepo
}
else {
    $approvedVersion = Get-ApprovedReleaseVersion -ApiBaseUrl $resolvedApiBaseUrl
}

$shouldInstall = $false

if (-not $serviceExists -and -not $installedDeploymentTool -and -not $installedSensor) {
    Write-Output "No existing installation found - installing version $approvedVersion."
    $shouldInstall = $true
}
elseif ($installedDeploymentTool) {
    $installedVersionText = if ($installedDeploymentTool.DisplayVersion) { $installedDeploymentTool.DisplayVersion } else { 'unknown' }

    if ($installedDeploymentTool.Version -and ([Version]$approvedVersion -gt $installedDeploymentTool.Version)) {
        Write-Output "Upgrading Deployment Tool from $installedVersionText to $approvedVersion."
        $shouldInstall = $true
    }
    else {
        Write-Output "Deployment Tool is already installed and up to date (version $installedVersionText) - skipping MSI installation."

        if (-not $serviceExists) {
            Write-Warning "The Deployment Tool is installed but the '$ServiceName' service was not found."
            Write-Output "Attempting to finalize the existing Deployment Tool installation..."
            $shouldRunDeploymentToolInstallCheck = $true
        }
    }
}
elseif ($installedSensor) {
    $installedVersionText = if ($installedSensor.DisplayVersion) { $installedSensor.DisplayVersion } else { 'unknown' }

    if ($installedSensor.Version -and ([Version]$approvedVersion -gt $installedSensor.Version)) {
        Write-Output "Upgrading installed sensor from $installedVersionText to $approvedVersion."
        $shouldInstall = $true
    }
    else {
        Write-Output "Sensor is already installed and up to date (version $installedVersionText) - updating configuration only."
    }
}
else {
    Write-Output "Service already installed - updating configuration only."
}

if ($shouldInstall) {
    $ReleaseBaseUrl = "https://github.com/$GitHubRepo/releases/download/v$approvedVersion"
    $MsiUrl         = "$ReleaseBaseUrl/$MsiFileName"

    New-Item -ItemType Directory -Path $DownloadDir -Force | Out-Null

    try {
        Write-Output "Downloading CyberAlarm Secure Sensor version $approvedVersion..."
        Invoke-FileDownload -Uri $MsiUrl -OutFile $MsiPath

        if ($SkipPublisherVerification) {
            Write-Warning 'Skipping MSI publisher signature verification because -SkipPublisherVerification was specified.'
        }
        else {
            Write-Output "Verifying MSI publisher signature..."
            Assert-AuthenticodePublisher -Path $MsiPath -ExpectedCN $ExpectedPublisher
        }

        Write-Output "Installing (this may take a moment)..."
        $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $MsiLog = Join-Path $InstallerLogDir "CyberAlarmSecureSensor-install-$timestamp.log"
        $msi = Start-Process msiexec -ArgumentList "/i `"$MsiPath`" /quiet /norestart /l*v `"$MsiLog`" INSTALLFOLDER=`"$VelopackInstallDir`"" -Wait -NoNewWindow -PassThru

        if ($msi.ExitCode -eq 3010) {
            Write-Warning 'The MSI installer has requested a system reboot to complete installation. The service may not start correctly until the machine is restarted.'
        }
        elseif ($msi.ExitCode -ne 0) {
            Write-Output ""
            Write-Warning "MSI log: $MsiLog"
            Write-Warning "MSI retained at: $MsiPath"
            if (Test-Path $MsiLog) {
                Write-Warning "--- MSI failure lines (Return value 3 / Error / CustomAction) ---"
                $logLines = Get-Content $MsiLog
                $errorLines = $logLines | Where-Object { $_ -match 'Return value 3|Error\b|CustomAction.*returned actual error|CAQuietExec|failed|exception' }
                if ($errorLines) {
                    $errorLines | Write-Output
                }
                else {
                    Write-Warning "(No error pattern matched - dumping last 60 lines)"
                    $logLines | Select-Object -Last 60 | Write-Output
                }
            }
            throw "MSI installation failed with exit code $($msi.ExitCode). See log above for details."
        }

        Write-Output "Installation complete."
    }
    finally {
        # Always clean up the download directory unless the MSI install failed,
        # in which case the MSI is retained at $MsiPath for diagnostics.
        if (Test-Path $MsiPath) {
            $msiExitCode = if ($null -ne $msi) { $msi.ExitCode } else { -1 }
            if ($msiExitCode -in 0, 3010) {
                Remove-Item $DownloadDir -Recurse -Force -ErrorAction SilentlyContinue
            }
            else {
                Write-Warning "Installer files retained for diagnostics at: $DownloadDir"
            }
        }
        else {
            Remove-Item $DownloadDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# ---------------------------------------------------------------------------
# Write configuration
# ---------------------------------------------------------------------------
Write-Output "Writing configuration to $ConfigPath..."

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
            Write-Warning 'Suggested uninstall command:'
            Write-Warning "  $uninstallCommand"
        }

        throw 'Deployment Tool executable was not found, so the legacy Windows service installation could not be finalized.'
    }

    Invoke-DeploymentToolInstall -ExecutablePath $deploymentToolExecutablePath -InstallTo $VelopackInstallDir
}

# ---------------------------------------------------------------------------
# Start / restart service
# ---------------------------------------------------------------------------
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -eq 'Running') {
        Write-Output "Restarting service..."
        Restart-Service -Name $ServiceName -Force
    }
    else {
        Write-Output "Starting service..."
        try {
            Start-Service -Name $ServiceName
        }
        catch {
            Write-Warning "Service '$ServiceName' could not be started. If a reboot was requested during installation, restart the machine and start the service manually. Error: $($_.Exception.Message)"
        }
    }

    $svc.Refresh()
    if ($svc.Status -eq 'Running') {
        Write-Output "CyberAlarm Secure Sensor is running."
    }
    else {
        Write-Warning "Service '$ServiceName' is in '$($svc.Status)' state. Check the Windows Event Log for details."
    }
}
else {
    Write-Warning "Service '$ServiceName' was not found after install. Check Windows Event Log for details."
}

# ---------------------------------------------------------------------------
# Windows Firewall rules
# ---------------------------------------------------------------------------
$firewallRuleName = "CyberAlarm Secure Sensor - Syslog"
Write-Output "Configuring Windows Firewall rules for syslog (TCP/UDP port 514)..."
foreach ($protocol in @('TCP', 'UDP')) {
    $ruleName = "$firewallRuleName ($protocol)"
    $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Output "  Firewall rule '$ruleName' already exists - skipping."
    }
    else {
        New-NetFirewallRule `
            -DisplayName $ruleName `
            -Direction Inbound `
            -Action Allow `
            -Protocol $protocol `
            -LocalPort 514 `
            -Profile Any `
            -Description "Allow inbound syslog traffic to CyberAlarm Secure Sensor" | Out-Null
        Write-Output "  Created firewall rule '$ruleName'."
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

$osProductType  = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType
$isWorkstationOs = $osProductType -eq 1  # 1 = Workstation; 2 = Domain Controller; 3 = Server
$acSleepSeconds  = Get-AcSleepTimeoutSeconds
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