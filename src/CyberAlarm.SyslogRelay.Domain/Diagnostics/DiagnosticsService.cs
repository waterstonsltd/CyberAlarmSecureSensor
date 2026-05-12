using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Text.Json;
using CyberAlarm.SyslogRelay.Common.Status.Models;
using CyberAlarm.SyslogRelay.Domain.Pipeline;
using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Domain.State;
using CyberAlarm.SyslogRelay.Domain.Upload.Scheduling;
using Microsoft.Extensions.Options;

#pragma warning disable S6966 // TextWriter.WriteLine is used intentionally (output is in-memory StringWriter)
#pragma warning disable SA1501 // Statement on single line — acceptable in terse output helpers
#pragma warning disable SA1503 // Braces omitted — acceptable in terse output helpers
#pragma warning disable SA1513 // Closing brace blank line — relaxed in output helpers

namespace CyberAlarm.SyslogRelay.Domain.Diagnostics;

public sealed class DiagnosticsService(
    IFileManager fileManager,
    IPlatformService platformService,
    IOptions<RelayOptions> relayOptions,
    IOptions<PipelineOptions> pipelineOptions,
    IOptions<ScheduleOptions> scheduleOptions,
    IHttpClientFactory httpClientFactory)
{
    private const string Tick = "✓";
    private const string Warn = "⚠";
    private const string Arrow = "→";
    private const string ServiceName = "CyberAlarm Syslog Relay";

    private readonly IFileManager _fileManager = fileManager;
    private readonly IPlatformService _platformService = platformService;
    private readonly RelayOptions _options = relayOptions.Value;
    private readonly PipelineOptions _pipelineOptions = pipelineOptions.Value;
    private readonly ScheduleOptions _scheduleOptions = scheduleOptions.Value;
    private readonly IHttpClientFactory _httpClientFactory = httpClientFactory;

    public async Task RunAsync(TextWriter output, CancellationToken cancellationToken)
    {
        var platform = _platformService.GetPlatform();
        var platformType = _platformService.GetPlatformType();
        var dataPath = _fileManager.GetDataPath();

        var state = await _fileManager.DeserialiseFromFileAsync<RelayState>(
            Path.Combine(dataPath, "state.json"), cancellationToken);
        var status = await _fileManager.DeserialiseFromFileAsync<RelayStatus>(
            Path.Combine(dataPath, "status.json"), cancellationToken);

        WriteHeader(output, platform, dataPath);
        await WriteAppHealth(output, dataPath, cancellationToken);

        if (OperatingSystem.IsWindows())
        {
            WriteWindowsServiceStatus(output, state);
        }

        if (platform.RunningInContainer)
        {
            WriteDockerHints(output);
        }

        await WriteRegistrationState(output, state, status, cancellationToken);
        await WriteIngestPipeline(output, cancellationToken);
        WriteFailedFiles(output);
        await WriteFirewallHistory(output, cancellationToken);

        if (!platform.RunningInContainer)
        {
            WriteNetworkAddresses(output, platformType);
        }
        else
        {
            WriteDockerNetworkHint(output);
        }

        if (OperatingSystem.IsWindows())
        {
            await WriteWindowsFirewallRules(output);
        }

        if (_options.FileWatcherEnabled)
        {
            WriteDropFolder(output);
        }

        if (_options.TlsEnabled)
        {
            WriteTlsStatus(output);
        }

        await WriteConnectivityProbes(output, status, cancellationToken);
        await WriteRecentLogs(output, dataPath, cancellationToken);
    }

    private void WriteHeader(TextWriter writer, Platform platform, string dataPath)
    {
        writer.WriteLine("╔══════════════════════════════════════════════════════════════╗");
        writer.WriteLine("║       CyberAlarm Secure Sensor — Diagnostics                 ║");
        writer.WriteLine("╚══════════════════════════════════════════════════════════════╝");
        writer.WriteLine();
        writer.WriteLine($"  Version    : {_options.BuildVersion}");
        writer.WriteLine($"  Platform   : {platform.Os}");
        writer.WriteLine($"  Runtime    : {platform.Runtime}");
        writer.WriteLine($"  Docker     : {(platform.RunningInContainer ? "Yes" : "No")}");
        writer.WriteLine($"  Data path  : {dataPath}");
        writer.WriteLine($"  Time (UTC) : {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}");
        writer.WriteLine();
    }

    private async Task WriteAppHealth(TextWriter writer, string dataPath, CancellationToken cancellationToken)
    {
        WriteSectionHeader(writer, "App Health");

        var healthCheckPath = Path.Combine(dataPath, "healthcheck.json");

        if (!File.Exists(healthCheckPath))
        {
            writer.WriteLine($"  {Warn}  healthcheck.json not found — the service may not have started yet.");
            if (OperatingSystem.IsWindows())
            {
                writer.WriteLine($"     Check: Get-Service \"{ServiceName}\"");
            }
            else if (_platformService.GetPlatform().RunningInContainer)
            {
                writer.WriteLine($"     Check: docker compose ps");
            }
            writer.WriteLine();
            return;
        }

        var healthData = await _fileManager.DeserialiseFromFileAsync<Dictionary<string, JsonElement?>>(
            healthCheckPath, cancellationToken);

        if (healthData is null || healthData.Count == 0)
        {
            writer.WriteLine($"  {Warn}  Health check file is empty or unreadable.");
            writer.WriteLine();
            return;
        }

        var anyUnhealthy = false;
        foreach (var (service, entry) in healthData)
        {
            if (entry is null)
            {
                writer.WriteLine($"  {Warn}  {service,-35} Not yet reported");
                anyUnhealthy = true;
                continue;
            }

            var timestamp = entry.Value.TryGetProperty("Timestamp", out var tsProp)
                ? tsProp.GetDateTime()
                : (DateTime?)null;

            // Status is serialised as an integer (0=Healthy, 1=Degraded, 2=Unhealthy) or as a string
            string? statusStr = null;
            if (entry.Value.TryGetProperty("Status", out var sProp))
            {
                statusStr = sProp.ValueKind == JsonValueKind.Number
                    ? sProp.GetInt32() switch { 0 => "Healthy", 1 => "Degraded", 2 => "Unhealthy", var n => $"Status({n})" }
                    : sProp.GetString();
            }

            if (statusStr != "Healthy")
            {
                var tsDisplay = timestamp.HasValue ? timestamp.Value.ToString("HH:mm:ss") + " UTC" : string.Empty;
                writer.WriteLine($"  {Warn}  {service,-35} {statusStr ?? "Unknown",-12} {tsDisplay}");
                anyUnhealthy = true;
            }
        }

        if (!anyUnhealthy)
        {
            writer.WriteLine($"  {Tick}  All services healthy.");
        }

        writer.WriteLine();
    }

    [SupportedOSPlatform("windows")]
    private static void WriteWindowsServiceStatus(TextWriter writer, RelayState? state)
    {
        WriteSectionHeader(writer, "Windows Service");

        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = $"query \"{ServiceName}\"",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            });

            var output = process?.StandardOutput.ReadToEnd() ?? string.Empty;
            process?.WaitForExit();

            if (output.Contains("RUNNING", StringComparison.OrdinalIgnoreCase))
            {
                writer.WriteLine($"  {Tick}  Service is running.");
            }
            else if (output.Contains("STOPPED", StringComparison.OrdinalIgnoreCase))
            {
                writer.WriteLine($"  {Warn}  Service is stopped.");

                if (state?.IsUploadBlocked == true)
                {
                    writer.WriteLine($"     The service stopped itself due to a fatal authentication error.");
                    writer.WriteLine($"     See the 'Registration & Upload State' section below for details.");
                }
                else
                {
                    writer.WriteLine($"     To start: Start-Service \"{ServiceName}\"");
                    writer.WriteLine($"     Logs:     %ProgramData%\\syslog-relay\\logs\\");
                }
            }
            else
            {
                writer.WriteLine($"  {Warn}  Could not determine service status. The service may not be installed.");
                writer.WriteLine($"     Re-run the installer: Install-CyberAlarmSecureSensor.ps1 -RegistrationToken <TOKEN>");
            }
        }
        catch (Exception)
        {
            writer.WriteLine($"  {Warn}  Could not query service status. The service may not be installed.");
            writer.WriteLine($"     Re-run the installer: Install-CyberAlarmSecureSensor.ps1 -RegistrationToken <TOKEN>");
        }

        writer.WriteLine();
    }

    private static void WriteDockerHints(TextWriter writer)
    {
        WriteSectionHeader(writer, "Docker");
        writer.WriteLine("  Running inside a Docker container. To check from the host:");
        writer.WriteLine("    docker inspect --format='{{.State.Health.Status}}' syslog-relay");
        writer.WriteLine("    docker compose logs --tail 50 syslog-relay");
        writer.WriteLine();
    }

    private async Task WriteRegistrationState(
        TextWriter writer, RelayState? state, RelayStatus? status, CancellationToken cancellationToken)
    {
        WriteSectionHeader(writer, "Registration & Upload State");

        if (state is null)
        {
            writer.WriteLine($"  {Warn}  state.json not found — service has not completed first-run initialisation.");
            writer.WriteLine($"     Check the service is running and review logs for initialisation errors.");
            writer.WriteLine();
            return;
        }

        writer.WriteLine($"  Registered        : {(state.IsRegistered ? Tick + "  Yes" : Warn + "  No")}");
        writer.WriteLine($"  Upload blocked    : {(state.IsUploadBlocked ? Warn + "  Yes" : Tick + "  No")}");
        writer.WriteLine($"  Uploads disabled  : {(status?.UploadsDisabled == true ? Warn + "  Yes (server-side flag)" : Tick + "  No")}");

        if (!state.IsRegistered)
        {
            writer.WriteLine();
            writer.WriteLine($"  {Warn}  The sensor is not registered. Re-run the installer with a valid registration token.");
        }

        if (state.IsUploadBlocked)
        {
            writer.WriteLine();
            writer.WriteLine($"  {Warn}  Upload was blocked by a fatal authentication or permission error.");
            writer.WriteLine($"     The service stopped itself to prevent repeated failed attempts.");
            writer.WriteLine($"     This is an AUTHENTICATION problem, not a firewall/connectivity issue.");

            var blockingEntry = await FindUploadBlockedLogEntry(cancellationToken);
            if (blockingEntry is not null)
            {
                writer.WriteLine();
                writer.WriteLine($"     Cause found in logs:");
                writer.WriteLine($"       [{blockingEntry.Timestamp:yyyy-MM-dd HH:mm:ss} UTC] {blockingEntry.Message}");
            }

            writer.WriteLine();
            writer.WriteLine($"     Resolution:");
            writer.WriteLine($"       1. Check the registration token is valid in the CyberAlarm portal.");
            writer.WriteLine($"       2. Re-run the installer: Install-CyberAlarmSecureSensor.ps1 -RegistrationToken <TOKEN>");
        }

        if (status?.UploadsDisabled == true)
        {
            writer.WriteLine();
            writer.WriteLine($"  {Warn}  Uploads have been disabled by the server. Contact CyberAlarm support.");
        }

        writer.WriteLine();
    }

    private async Task WriteIngestPipeline(TextWriter writer, CancellationToken cancellationToken)
    {
        WriteSectionHeader(writer, "Ingest Pipeline");

        var folders = new (string Label, string Path)[]
        {
            ("logs/",          _fileManager.GetLogsFolder()),
            ("processing/",    _fileManager.GetProcessingFolder()),
            ("source-groups/", _fileManager.GetSourceGroupFolder()),
            ("upload/",        _fileManager.GetUploadFolder()),
            ("failed/",        _fileManager.GetFailedFolder()),
        };

        var counts = new Dictionary<string, int>();
        foreach (var (label, path) in folders)
        {
            var count = _fileManager.ListFilesInDirectory(path).Count();
            counts[label] = count;
            writer.WriteLine($"  {label,-22} {count,4} file{(count == 1 ? string.Empty : "s")}");
        }

        writer.WriteLine();

        // Parse stats from the newest .tmp/logs/ file
        var logsFolder = _fileManager.GetLogsFolder();
        var logDataFiles = Directory.Exists(logsFolder)
            ? Directory.GetFiles(logsFolder)
                .OrderByDescending(f => File.GetLastWriteTimeUtc(f))
                .ToList()
            : [];

        if (logDataFiles.Count > 0)
            await WriteParseStats(writer, logDataFiles[0], cancellationToken);

        // Infer last activity from file modification times
        var pipelineDirs = new[]
        {
            _fileManager.GetLogsFolder(),
            _fileManager.GetSourceGroupFolder(),
            _fileManager.GetUploadFolder(),
        };

        var newestMtime = pipelineDirs
            .Where(Directory.Exists)
            .SelectMany(d => Directory.GetFiles(d, "*", SearchOption.AllDirectories))
            .Select(f => File.GetLastWriteTimeUtc(f))
            .DefaultIfEmpty(DateTime.MinValue)
            .Max();

        var staleThreshold = TimeSpan.FromMinutes(_scheduleOptions.UploadIntervalInMinutes * 2);

        if (newestMtime == DateTime.MinValue)
        {
            var appLogFiles = Directory.Exists(Path.Combine(_fileManager.GetDataPath(), "logs"))
                && Directory.GetFiles(Path.Combine(_fileManager.GetDataPath(), "logs"), "relay-*.json").Length > 0;

            if (!appLogFiles)
                writer.WriteLine($"  {Warn}  No syslog data and no log files found. The service may not have started yet.");
            else
                writer.WriteLine($"  {Warn}  No syslog data received yet. Ensure your syslog sender is pointed at the addresses in the Network section.");
        }
        else if (DateTime.UtcNow - newestMtime > staleThreshold && counts["logs/"] == 0)
        {
            var ago = FormatAge(DateTime.UtcNow - newestMtime);
            writer.WriteLine($"  {Warn}  Last syslog activity was ~{ago} ago.");
            writer.WriteLine($"     If this host has a dynamic/DHCP IP, your syslog senders may be");
            writer.WriteLine($"     pointed at an old IP. Current addresses are in the Network section.");
        }
        else if (counts["upload/"] > 0)
        {
            writer.WriteLine($"  ℹ  {counts["upload/"]} bundle(s) ready to upload. See the Connectivity section.");
        }
        else
        {
            writer.WriteLine($"  {Tick}  Data pipeline looks healthy.");
        }

        if (_pipelineOptions.UploadRawLogs)
        {
            writer.WriteLine();
            writer.WriteLine($"  {Warn}  Raw log uploads are ENABLED (UploadRawLogs=true).");
            writer.WriteLine($"     This uploads ALL syslog lines including unparsed ones and increases upload volume.");
            writer.WriteLine($"     To disable: set \"UploadRawLogs\": false in appsettings and restart.");
        }

        writer.WriteLine();
    }

    private static async Task WriteParseStats(TextWriter writer, string logFilePath, CancellationToken cancellationToken)
    {
        var counts = new Dictionary<string, int>
        {
            ["Success"] = 0,
            ["UnableToPatternMatch"] = 0,
            ["UnableToParse"] = 0,
            ["LocalOnlyEvent"] = 0,
            ["Ignored"] = 0,
        };

        var total = 0;
        const int MaxSample = 500;

        try
        {
            await using var stream = File.OpenRead(logFilePath);
            using var reader = new StreamReader(stream);

            while (total < MaxSample)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var line = await reader.ReadLineAsync(cancellationToken);
                if (line is null) break;
                if (string.IsNullOrWhiteSpace(line)) continue;

                try
                {
                    using var doc = JsonDocument.Parse(line);
                    if (doc.RootElement.TryGetProperty("ValidationStatus", out var vs))
                    {
                        var key = vs.GetString() ?? string.Empty;
                        if (counts.TryGetValue(key, out var existing))
                        {
                            counts[key] = existing + 1;
                        }

                        total++;
                    }
                }
                catch (JsonException) { /* skip malformed lines */ }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            writer.WriteLine($"  (Could not sample parse stats: {ex.Message})");
            return;
        }

        if (total == 0) return;

        writer.WriteLine($"  Parse stats (sample of {total} events from newest log file):");
        writer.WriteLine($"    {"Success",-25} {counts["Success"],4}   will be uploaded");

        if (counts["UnableToPatternMatch"] > 0)
            writer.WriteLine($"    {"UnableToPatternMatch",-25} {counts["UnableToPatternMatch"],4}   no parser matched — device may not be supported");

        if (counts["UnableToParse"] > 0)
            writer.WriteLine($"    {"UnableToParse",-25} {counts["UnableToParse"],4}   parser matched but failed — check firmware version");

        if (counts["LocalOnlyEvent"] > 0)
            writer.WriteLine($"    {"LocalOnlyEvent",-25} {counts["LocalOnlyEvent"],4}   filtered as local/private traffic (not uploaded)");

        if (counts["Ignored"] > 0)
            writer.WriteLine($"    {"Ignored",-25} {counts["Ignored"],4}   matched ignore rules");

        var unparseable = counts["UnableToPatternMatch"] + counts["UnableToParse"];
        if (total > 0 && (double)unparseable / total > 0.5)
        {
            writer.WriteLine();
            writer.WriteLine($"  {Warn}  More than 50% of sampled events cannot be parsed.");
            writer.WriteLine($"     To upload raw syslog data regardless of parse failures:");
            writer.WriteLine($"       1. Set \"UploadRawLogs\": true in appsettings and restart.");
            writer.WriteLine($"     Note: raw uploads include unfiltered data and increase upload volume.");
        }

        writer.WriteLine();
    }

    private void WriteFailedFiles(TextWriter writer)
    {
        var failedFolder = _fileManager.GetFailedFolder();
        var files = _fileManager.ListFilesInDirectory(failedFolder).ToList();

        if (files.Count == 0) return;

        WriteSectionHeader(writer, "Failed Files");
        writer.WriteLine($"  {files.Count} file(s) in .tmp/failed/ — these will not be retried automatically.");
        writer.WriteLine();

        foreach (var filePath in files)
        {
            var name = Path.GetFileName(filePath);
            try
            {
                var lines = File.ReadAllLines(filePath);
                var parseError = TryValidateNdjson(lines);

                if (parseError is null)
                    writer.WriteLine($"  {Tick}  {name,-50} {lines.Length,4} lines  valid NDJSON");
                else
                    writer.WriteLine($"  {Warn}  {name,-50} corrupted — {parseError}");
            }
            catch (Exception ex)
            {
                writer.WriteLine($"  {Warn}  {name,-50} could not read: {ex.Message}");
            }
        }

        writer.WriteLine();
    }

    private static string? TryValidateNdjson(string[] lines)
    {
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (string.IsNullOrWhiteSpace(line)) continue;

            try
            {
                JsonDocument.Parse(line).Dispose();
            }
            catch (JsonException ex)
            {
                var msg = ex.Message.Length > 80 ? ex.Message[..80] : ex.Message;
                return $"JSON error at line {i + 1}: {msg}";
            }
        }

        return null;
    }

    private async Task WriteFirewallHistory(TextWriter writer, CancellationToken cancellationToken)
    {
        WriteSectionHeader(writer, "Syslog Source History");

        // Source 1: source-groups folder (persistent, survives log rotation)
        var sourceGroupFolder = _fileManager.GetSourceGroupFolder();
        var sourceEntries = new List<(string Source, DateTime LastActive)>();

        if (Directory.Exists(sourceGroupFolder))
        {
            foreach (var method in _fileManager.ListDirectoryNamesInDirectory(sourceGroupFolder))
            {
                var methodPath = Path.Combine(sourceGroupFolder, method);
                foreach (var key in _fileManager.ListDirectoryNamesInDirectory(methodPath))
                {
                    var keyPath = Path.Combine(methodPath, key);
                    var dataFiles = Directory.Exists(keyPath)
                        ? Directory.GetFiles(keyPath, "*", SearchOption.AllDirectories)
                        : [];

                    var lastActive = dataFiles.Length > 0
                        ? dataFiles.Max(f => File.GetLastWriteTimeUtc(f))
                        : Directory.GetLastWriteTimeUtc(keyPath);

                    sourceEntries.Add(($"{method}/{key}", lastActive));
                }
            }
        }

        if (sourceEntries.Count > 0)
        {
            var staleThreshold = TimeSpan.FromMinutes(_scheduleOptions.UploadIntervalInMinutes * 2);
            writer.WriteLine("  Known syslog sources (from processed data — survives log rotation):");
            writer.WriteLine($"  {"Source",-35} {"Last Active (UTC)",-22} Status");
            writer.WriteLine($"  {"─────────────────────────────────",-35} {"────────────────────",-22} ──────────────────────");

            foreach (var (source, lastActive) in sourceEntries.OrderByDescending(e => e.LastActive))
            {
                var age = DateTime.UtcNow - lastActive;
                var statusMark = age > staleThreshold
                    ? $"{Warn} no activity in {FormatAge(age)}"
                    : Tick;
                writer.WriteLine($"  {source,-35} {lastActive:yyyy-MM-dd HH:mm}        {statusMark}");
            }
        }
        else
        {
            writer.WriteLine($"  No processed syslog sources on record yet.");
        }

        writer.WriteLine();

        // Source 2: CLEF log scan (live connection events, Debug level only)
        var connections = await ScanLogsForConnections(cancellationToken);

        if (connections.Count > 0)
        {
            writer.WriteLine("  TCP connection events (from recent CLEF logs):");
            writer.WriteLine($"  {"Client IP",-22} {"Last Connected (UTC)",-22} {"Last Disconnected (UTC)",-24} Status");
            writer.WriteLine($"  {"─────────────────────",-22} {"────────────────────",-22} {"──────────────────────",-24} ──────");

            foreach (var (ip, lastConnected, lastDisconnected) in connections.OrderByDescending(c => c.LastConnected))
            {
                var connStr = lastConnected.HasValue ? lastConnected.Value.ToString("yyyy-MM-dd HH:mm") : "—";
                var discStr = lastDisconnected.HasValue ? lastDisconnected.Value.ToString("yyyy-MM-dd HH:mm") : "—";
                string connStatus;
                if (lastConnected > lastDisconnected)
                {
                    connStatus = "Active";
                }
                else
                {
                    connStatus = "Disconnected";
                }
                writer.WriteLine($"  {ip,-22} {connStr,-22} {discStr,-24} {connStatus}");
            }
        }
        else
        {
            writer.WriteLine($"  No TCP connection events found in recent logs.");
            writer.WriteLine($"  Connection events are logged at Debug level. To enable:");
            writer.WriteLine($"    Add to appsettings: \"Serilog\": {{ \"MinimumLevel\": {{ \"Default\": \"Debug\" }} }}");
        }

        writer.WriteLine();
    }

    private async Task<List<(string Ip, DateTime? LastConnected, DateTime? LastDisconnected)>> ScanLogsForConnections(
        CancellationToken cancellationToken)
    {
        var dataPath = _fileManager.GetDataPath();
        var logsPath = Path.Combine(dataPath, "logs");

        if (!Directory.Exists(logsPath)) return [];

        var logFiles = Directory.GetFiles(logsPath, "relay-*.json")
            .OrderByDescending(f => f)
            .Take(3)
            .ToList();

        var connected = new Dictionary<string, DateTime>(StringComparer.Ordinal);
        var disconnected = new Dictionary<string, DateTime>(StringComparer.Ordinal);

        foreach (var file in logFiles)
        {
            try
            {
                await using var stream = File.OpenRead(file);
                using var reader = new StreamReader(stream);

                while (true)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var line = await reader.ReadLineAsync(cancellationToken);
                    if (line is null) break;
                    if (string.IsNullOrWhiteSpace(line)) continue;

                    try
                    {
                        using var doc = JsonDocument.Parse(line);
                        var root = doc.RootElement;

                        if (!root.TryGetProperty("@mt", out var mtProp)) continue;
                        var template = mtProp.GetString();
                        if (template is null) continue;

                        var isConnect = template.Contains("[{Client}] connected.", StringComparison.Ordinal);
                        var isDisconnect = template.Contains("[{Client}] disconnected.", StringComparison.Ordinal);
                        if (!isConnect && !isDisconnect) continue;

                        if (!root.TryGetProperty("Client", out var clientProp)) continue;
                        var clientRaw = clientProp.GetString() ?? string.Empty;
                        var ip = ParseClientIp(clientRaw);
                        if (ip is null) continue;

                        var timestamp = root.TryGetProperty("@t", out var tsProp)
                            && DateTime.TryParse(tsProp.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed)
                                ? parsed
                                : DateTime.UtcNow;

                        if (isConnect)
                        {
                            if (!connected.TryGetValue(ip, out var prev) || timestamp > prev)
                                connected[ip] = timestamp;
                        }
                        else
                        {
                            if (!disconnected.TryGetValue(ip, out var prev) || timestamp > prev)
                                disconnected[ip] = timestamp;
                        }
                    }
                    catch (JsonException) { /* skip malformed line */ }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _ = ex; // skip unreadable file
            }
        }

        var allIps = connected.Keys.Union(disconnected.Keys, StringComparer.Ordinal).ToHashSet();
        return [.. allIps.Select(ip => (
            ip,
            connected.TryGetValue(ip, out var c) ? (DateTime?)c : null,
            disconnected.TryGetValue(ip, out var d) ? (DateTime?)d : null))];
    }

    private static string? ParseClientIp(string client)
    {
        // Client format is typically "192.168.1.1:12345"
        var colonIdx = client.LastIndexOf(':');
        if (colonIdx > 0)
        {
            return client[..colonIdx];
        }

        return client.Length > 0 ? client : null;
    }

    private void WriteNetworkAddresses(TextWriter writer, PlatformType platformType)
    {
        WriteSectionHeader(writer, "Network");
        writer.WriteLine("  Point your syslog sender at one of these addresses:");
        writer.WriteLine();

        var addresses = NetworkInterface.GetAllNetworkInterfaces()
            .Where(ni => ni.OperationalStatus == OperationalStatus.Up
                         && ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .SelectMany(ni => ni.GetIPProperties().UnicastAddresses)
            .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
            .Select(a => a.Address.ToString())
            .Distinct()
            .ToList();

        foreach (var ip in addresses)
        {
            var ports = $"TCP/UDP {_options.TcpPort}";
            if (_options.TlsEnabled)
                ports += $", TLS {_options.TlsPort}";
            writer.WriteLine($"    {ip,-22} {ports}");
        }

        if (addresses.Count == 0)
            writer.WriteLine($"  {Warn}  No network addresses found.");

        if (platformType == PlatformType.Linux)
        {
            writer.WriteLine();
            writer.WriteLine($"  Check host firewall (iptables) allows inbound port {_options.TcpPort}:");
            writer.WriteLine($"    sudo iptables -L INPUT -n | grep {_options.TcpPort}");
            writer.WriteLine($"  Check port is not in use by another process:");
            writer.WriteLine($"    ss -tulpn | grep ':{_options.TcpPort}'");
        }

        writer.WriteLine();
    }

    private static void WriteDockerNetworkHint(TextWriter writer)
    {
        WriteSectionHeader(writer, "Network");
        writer.WriteLine("  Running in Docker — point your syslog sender at the host machine's IP on TCP/UDP 514.");
        writer.WriteLine("  To find the host IP from the Docker host:");
        writer.WriteLine("    hostname -I");
        writer.WriteLine("    ip route | grep default");
        writer.WriteLine();
    }

    [SupportedOSPlatform("windows")]
    private async Task WriteWindowsFirewallRules(TextWriter writer)
    {
        WriteSectionHeader(writer, "Windows Firewall");

        var ruleNames = new[]
        {
            ("CyberAlarm Secure Sensor - Syslog (TCP)", "TCP"),
            ("CyberAlarm Secure Sensor - Syslog (UDP)", "UDP"),
        };

        foreach (var (ruleName, proto) in ruleNames)
        {
            var exists = await CheckFirewallRuleExists(ruleName);
            if (exists)
            {
                writer.WriteLine($"  {Tick}  Rule exists: {ruleName}");
            }
            else
            {
                writer.WriteLine($"  {Warn}  Rule missing: {ruleName}");
                writer.WriteLine($"     To create:");
                writer.WriteLine($"       New-NetFirewallRule -DisplayName \"{ruleName}\" \\");
                writer.WriteLine($"         -Direction Inbound -Action Allow -Protocol {proto} \\");
                writer.WriteLine($"         -LocalPort {_options.TcpPort} -Profile Any");
            }
        }

        writer.WriteLine();

        var portConflict = CheckPortConflict(_options.TcpPort);
        if (portConflict)
        {
            writer.WriteLine($"  {Warn}  Port {_options.TcpPort} appears to be in use by another process.");
            writer.WriteLine($"     Check with:");
            writer.WriteLine($"       Get-NetTCPConnection -LocalPort {_options.TcpPort} -ErrorAction SilentlyContinue");
            writer.WriteLine($"       Get-NetUDPEndpoint   -LocalPort {_options.TcpPort} -ErrorAction SilentlyContinue");
        }
        else
        {
            writer.WriteLine($"  {Tick}  Port {_options.TcpPort} is available (not in use by another process).");
        }

        writer.WriteLine();
    }

    [SupportedOSPlatform("windows")]
    private static async Task<bool> CheckFirewallRuleExists(string ruleName)
    {
        try
        {
            using var proc = new Process();
            proc.StartInfo = new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = $"advfirewall firewall show rule name=\"{ruleName}\"",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            proc.Start();
            var output = await proc.StandardOutput.ReadToEndAsync();
            await proc.WaitForExitAsync();
            return !output.Contains("No rules match the specified criteria", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static bool CheckPortConflict(int port)
    {
        try
        {
            var listener = new TcpListener(IPAddress.Any, port);
            listener.Start();
            listener.Stop();
            return false;
        }
        catch (SocketException)
        {
            return true;
        }
    }

    private void WriteDropFolder(TextWriter writer)
    {
        WriteSectionHeader(writer, "File Watcher Drop Folder");
        var path = _options.FileWatcherDropPath;
        writer.WriteLine($"  Path   : {path}");

        if (!Directory.Exists(path))
        {
            writer.WriteLine($"  {Warn}  Drop folder does not exist. Create it:");
            if (OperatingSystem.IsWindows())
                writer.WriteLine($"     New-Item -ItemType Directory -Path \"{path}\"");
            else
                writer.WriteLine($"     mkdir -p \"{path}\"");
        }
        else
        {
            var count = Directory.GetFiles(path, "*", SearchOption.AllDirectories).Length;
            writer.WriteLine($"  {Tick}  Folder exists. Files: {count}");
        }

        writer.WriteLine();
    }

    private void WriteTlsStatus(TextWriter writer)
    {
        WriteSectionHeader(writer, "TLS Configuration");
        writer.WriteLine($"  TLS listener port : {_options.TlsPort}");
        writer.WriteLine($"  Certificate path  : {_options.TlsCertificatePath}");

        if (!File.Exists(_options.TlsCertificatePath))
            writer.WriteLine($"  {Warn}  Certificate file not found — TLS listener will fail to start.");
        else
            writer.WriteLine($"  {Tick}  Certificate file exists.");

        if (!_options.AllowPlaintextListenersWhenTlsEnabled)
        {
            writer.WriteLine();
            writer.WriteLine($"  ℹ  Plaintext TCP/UDP on port {_options.TcpPort} are DISABLED (AllowPlaintextListenersWhenTlsEnabled=false).");
            writer.WriteLine($"     Syslog senders must use TLS on port {_options.TlsPort}.");
        }

        writer.WriteLine();
    }

    private async Task WriteConnectivityProbes(TextWriter writer, RelayStatus? status, CancellationToken cancellationToken)
    {
        WriteSectionHeader(writer, "Connectivity Probes");

        if (status is null)
        {
            writer.WriteLine($"  {Warn}  status.json not found — upload destination unknown. Checking API only:");
            writer.WriteLine();
            await ProbeAndWrite(writer, ExtractHost(_options.ApiBaseUrl), 443, $"API ({ExtractHost(_options.ApiBaseUrl)}:443)", cancellationToken);
            await ProbeHttpHead(writer, _options.StatusEndpoint, "API status endpoint (HTTP HEAD)", cancellationToken);
            writer.WriteLine();
            writer.WriteLine($"  Once the service has initialised, status.json will be created and");
            writer.WriteLine($"  the full upload path can be probed.");
            writer.WriteLine();
            return;
        }

        var bucket = _options.Bucket;

        if (!status.StorageAccounts.TryGetValue(bucket, out var storageAccountName)
            || string.IsNullOrEmpty(storageAccountName))
        {
            writer.WriteLine($"  {Warn}  Could not determine upload host — bucket '{bucket}' not found in status.json.");
            writer.WriteLine($"     This may indicate a corrupted registration. Contact support.");
            writer.WriteLine();
            await ProbeAndWrite(writer, ExtractHost(_options.ApiBaseUrl), 443, $"API ({ExtractHost(_options.ApiBaseUrl)}:443)", cancellationToken);
            await ProbeHttpHead(writer, _options.StatusEndpoint, "API status endpoint", cancellationToken);
            writer.WriteLine();
            return;
        }

        var storageHost = $"{storageAccountName}.blob.core.windows.net";

        var sftpOk = await ProbeAndWrite(writer, storageHost, 22, $"SFTP  {storageHost}:22  (primary upload)", cancellationToken);
        var httpsOk = await ProbeAndWrite(writer, storageHost, 443, $"HTTPS {storageHost}:443  (fallback upload — step 2)", cancellationToken);
        var apiOk = await ProbeAndWrite(writer, ExtractHost(_options.ApiBaseUrl), 443, $"HTTPS {ExtractHost(_options.ApiBaseUrl)}:443  (API / fallback — step 1)", cancellationToken);
        await ProbeHttpHead(writer, _options.StatusEndpoint, "API status endpoint (HTTP HEAD)", cancellationToken);

        if (!sftpOk || !httpsOk || !apiOk)
        {
            writer.WriteLine();
            writer.WriteLine($"  {Warn}  One or more connectivity checks failed.");
            writer.WriteLine($"     Required outbound connections:");
            writer.WriteLine();
            writer.WriteLine($"    SFTP primary:       {storageHost,-52} port 22/TCP");
            writer.WriteLine($"    HTTPS fallback:");
            writer.WriteLine($"      step 1 (token):   {ExtractHost(_options.ApiBaseUrl),-52} port 443/TCP");
            writer.WriteLine($"      step 2 (upload):  {storageHost,-52} port 443/TCP");
            writer.WriteLine();

            if (OperatingSystem.IsWindows())
            {
                writer.WriteLine($"  Test with PowerShell:");
                writer.WriteLine($"    Test-NetConnection {storageHost} -Port 22");
                writer.WriteLine($"    Test-NetConnection {storageHost} -Port 443");
            }
            else
            {
                writer.WriteLine($"  Test with nc:");
                writer.WriteLine($"    nc -zv {storageHost} 22");
                writer.WriteLine($"    nc -zv {storageHost} 443");
            }

            if (!sftpOk && httpsOk && apiOk)
            {
                writer.WriteLine();
                writer.WriteLine($"  ℹ  SFTP (port 22) is blocked but HTTPS fallback looks reachable.");
                writer.WriteLine($"     Uploads should still succeed via the HTTPS fallback channel.");
            }
        }
        else
        {
            writer.WriteLine();
            writer.WriteLine($"  {Tick}  All connectivity checks passed.");
        }

        writer.WriteLine();
    }

    private static async Task<bool> ProbeAndWrite(TextWriter writer, string host, int port, string label, CancellationToken cancellationToken)
    {
        writer.Write($"  {Arrow} {label,-62} ");
        try
        {
            using var tcp = new TcpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            await tcp.ConnectAsync(host, port, cts.Token);
            writer.WriteLine($"{Tick} reachable");
            return true;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            writer.WriteLine("✗ timed out");
            return false;
        }
        catch
        {
            writer.WriteLine("✗ unreachable");
            return false;
        }
    }

    private async Task ProbeHttpHead(TextWriter writer, string url, string label, CancellationToken cancellationToken)
    {
        writer.Write($"  {Arrow} {label,-62} ");
        try
        {
            using var client = _httpClientFactory.CreateClient("diagnostics");
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            var response = await client.SendAsync(
                new HttpRequestMessage(HttpMethod.Head, url), cts.Token);
            writer.WriteLine($"{Tick} HTTP {(int)response.StatusCode}");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            writer.WriteLine("✗ timed out");
        }
        catch
        {
            writer.WriteLine("✗ unreachable");
        }
    }

    private static async Task WriteRecentLogs(TextWriter writer, string dataPath, CancellationToken cancellationToken)
    {
        WriteSectionHeader(writer, "Recent Log Activity");

        var logsPath = Path.Combine(dataPath, "logs");

        if (!Directory.Exists(logsPath))
        {
            writer.WriteLine($"  No log directory found at: {logsPath}");
            writer.WriteLine();
            return;
        }

        var logFiles = Directory.GetFiles(logsPath, "relay-*.json")
            .OrderByDescending(f => f)
            .Take(3)
            .ToList();

        if (logFiles.Count == 0)
        {
            writer.WriteLine($"  No log files found. Service may not have generated any logs yet.");
            writer.WriteLine();
            return;
        }

        var cutoff = DateTime.UtcNow.AddHours(-24);
        var grouped = new Dictionary<string, (int Count, DateTime MostRecent, string Level)>(StringComparer.Ordinal);
        var total24H = 0;
        var totalRead = 0;
        const int MaxLines = 500;

        foreach (var file in logFiles)
        {
            if (totalRead >= MaxLines) break;

            try
            {
                await using var stream = File.OpenRead(file);
                using var reader = new StreamReader(stream);

                while (totalRead < MaxLines)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var line = await reader.ReadLineAsync(cancellationToken);
                    if (line is null) break;
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    totalRead++;

                    try
                    {
                        using var doc = JsonDocument.Parse(line);
                        var root = doc.RootElement;

                        if (!root.TryGetProperty("@l", out var levelProp)) continue;
                        var level = levelProp.GetString() ?? string.Empty;
                        if (level is not ("Warning" or "Error" or "Fatal")) continue;

                        if (!root.TryGetProperty("@mt", out var mtProp)) continue;
                        var template = mtProp.GetString() ?? string.Empty;

                        var timestamp = root.TryGetProperty("@t", out var tsProp)
                            && DateTime.TryParse(tsProp.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsedTs)
                                ? parsedTs
                                : DateTime.UtcNow;

                        if (timestamp >= cutoff)
                            total24H++;

                        if (grouped.TryGetValue(template, out var existing))
                        {
                            grouped[template] = (
                                existing.Count + 1,
                                timestamp > existing.MostRecent ? timestamp : existing.MostRecent,
                                existing.Level);
                        }
                        else
                        {
                            grouped[template] = (1, timestamp, level);
                        }
                    }
                    catch (JsonException) { /* skip */ }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _ = ex;
            }
        }

        writer.WriteLine($"  Errors/Warnings in last 24 h: {total24H}");
        writer.WriteLine();

        if (grouped.Count == 0)
        {
            writer.WriteLine($"  {Tick}  No warnings or errors in recent logs.");
        }
        else
        {
            writer.WriteLine($"  {"Count",-7} {"Level",-6} {"Most Recent (UTC)",-22} Message Template");
            writer.WriteLine($"  {"─────",-7} {"─────",-6} {"──────────────────",-22} {"────────────────────────────────────────────────────────────"}");

            foreach (var (template, (count, mostRecent, level)) in grouped
                .OrderByDescending(g => g.Value.Count)
                .Take(15))
            {
                var shortLevel = level switch
                {
                    "Warning" => "WRN",
                    "Error" => "ERR",
                    "Fatal" => "FTL",
                    _ => level[..Math.Min(3, level.Length)],
                };
                var truncated = template.Length > 65 ? template[..65] + "…" : template;
                writer.WriteLine($"  {count,-7} [{shortLevel}]  {mostRecent:yyyy-MM-dd HH:mm}   {truncated}");
            }
        }

        writer.WriteLine();
    }

    private async Task<LogEntry?> FindUploadBlockedLogEntry(CancellationToken cancellationToken)
    {
        var dataPath = _fileManager.GetDataPath();
        var logsPath = Path.Combine(dataPath, "logs");

        if (!Directory.Exists(logsPath)) return null;

        var logFiles = Directory.GetFiles(logsPath, "relay-*.json")
            .OrderByDescending(f => f);

        var criticalPatterns = new[]
        {
            "Critical error while connecting to the server",
            "403 Forbidden",
            "SAS token rejected",
        };

        foreach (var file in logFiles)
        {
            try
            {
                await using var stream = File.OpenRead(file);
                using var reader = new StreamReader(stream);
                LogEntry? lastMatch = null;

                while (true)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var line = await reader.ReadLineAsync(cancellationToken);
                    if (line is null) break;
                    if (string.IsNullOrWhiteSpace(line)) continue;

                    try
                    {
                        using var doc = JsonDocument.Parse(line);
                        var root = doc.RootElement;

                        if (!root.TryGetProperty("@l", out var lv)) continue;
                        if (lv.GetString() is not "Fatal") continue;

                        if (!root.TryGetProperty("@mt", out var mt)) continue;
                        var template = mt.GetString();
                        if (template is null) continue;

                        if (!criticalPatterns.Any(p => template.Contains(p, StringComparison.OrdinalIgnoreCase)))
                            continue;

                        var ts = root.TryGetProperty("@t", out var tsProp)
                            && DateTime.TryParse(tsProp.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed)
                                ? parsed
                                : DateTime.UtcNow;

                        lastMatch = new LogEntry(ts, template);
                    }
                    catch { /* skip */ }
                }

                if (lastMatch is not null) return lastMatch;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _ = ex;
            }
        }

        return null;
    }

    private static string FormatAge(TimeSpan age)
    {
        if (age.TotalDays >= 1)
            return $"{(int)age.TotalDays} day{((int)age.TotalDays == 1 ? string.Empty : "s")}";
        if (age.TotalHours >= 1)
            return $"{(int)age.TotalHours} hour{((int)age.TotalHours == 1 ? string.Empty : "s")}";
        return $"{(int)age.TotalMinutes} minute{((int)age.TotalMinutes == 1 ? string.Empty : "s")}";
    }

    private static string ExtractHost(string url)
    {
        try { return new Uri(url).Host; }
        catch { return url; }
    }

    private static void WriteSectionHeader(TextWriter writer, string title)
    {
        var dashes = new string('─', Math.Max(0, 64 - title.Length - 4));
        writer.WriteLine($"── {title} {dashes}");
    }

    private sealed record LogEntry(DateTime Timestamp, string Message);
}
