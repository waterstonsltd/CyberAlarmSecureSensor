using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Text.Json;
using CyberAlarm.SyslogRelay.Common.Status.Models;
using CyberAlarm.SyslogRelay.Domain.Pipeline;
using CyberAlarm.SyslogRelay.Domain.Registration;
using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Domain.State;
using CyberAlarm.SyslogRelay.Domain.Upload.Scheduling;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

#pragma warning disable S6966 // TextWriter.WriteLine is used intentionally (output is in-memory StringWriter)

// Design intent: this service deliberately avoids reusing most main-project components.
////
//// The core services (StateService, StatusService, SecureUploader, SourceGrouper, etc.) carry
//// side effects, write behaviour, authentication dependencies, and retry logic that are
//// inappropriate in a read-only diagnostic context. Reusing them would risk mutating state,
//// triggering uploads, or hiding errors that diagnostics should surface.
////
//// This service is intentionally defensive: it reads files directly, tolerates missing or
//// corrupt data with null returns rather than exceptions, and produces human-readable output
//// without coupling to pipeline internals.
////
//// The one exception is RegistrationToken.GetBucket(), where the structural knowledge of the
//// token format belongs in a shared place. All other logic is local by design.

namespace CyberAlarm.SyslogRelay.Domain.Diagnostics;

public sealed class DiagnosticsService(
    IFileManager fileManager,
    IPlatformService platformService,
    IOptions<RelayOptions> relayOptions,
    IOptions<PipelineOptions> pipelineOptions,
    IOptions<ScheduleOptions> scheduleOptions,
    IHttpClientFactory httpClientFactory,
    IConfiguration configuration)
{
    private const string Tick = "✓";
    private const string Warn = "⚠";
    private const string Arrow = "->";
    private const string ServiceName = "CyberAlarm Syslog Relay";
    private const string LogFilePattern = "relay-*.json";
    private const string StatusSuccess = "Success";
    private const string StatusUnableToPatternMatch = "UnableToPatternMatch";
    private const string StatusUnableToParse = "UnableToParse";
    private const string StatusLocalOnlyEvent = "LocalOnlyEvent";
    private const string StatusIgnored = "Ignored";

    private static readonly string[] CriticalPatterns =
    [
        "Critical error while connecting to the server",
        "403 Forbidden",
        "SAS token rejected",
    ];

    private readonly IFileManager _fileManager = fileManager;
    private readonly IPlatformService _platformService = platformService;
    private readonly RelayOptions _options = relayOptions.Value;
    private readonly PipelineOptions _pipelineOptions = pipelineOptions.Value;
    private readonly ScheduleOptions _scheduleOptions = scheduleOptions.Value;
    private readonly IHttpClientFactory _httpClientFactory = httpClientFactory;
    private readonly IConfiguration _configuration = configuration;

    public async Task RunAsync(TextWriter output, CancellationToken cancellationToken)
        => await RunAsync(output, verbose: false, cancellationToken);

    public async Task RunAsync(TextWriter output, bool verbose, CancellationToken cancellationToken)
    {
        var platform = _platformService.GetPlatform();
        var platformType = _platformService.GetPlatformType();
        var dataPath = _fileManager.GetDataPath();

        var state = await _fileManager.DeserialiseFromFileAsync<RelayState>(
            Path.Combine(dataPath, "state.json"), cancellationToken);
        var status = await _fileManager.DeserialiseFromFileAsync<RelayStatus>(
            Path.Combine(dataPath, "status.json"), cancellationToken);

        if (verbose)
        {
            await RunVerboseAsync(output, platform, platformType, dataPath, state, status, cancellationToken);
        }
        else
        {
            await RunFocusedAsync(output, platform, platformType, dataPath, state, status, cancellationToken);
        }
    }

    private async Task RunVerboseAsync(
        TextWriter output,
        Platform platform,
        PlatformType platformType,
        string dataPath,
        RelayState? state,
        RelayStatus? status,
        CancellationToken cancellationToken)
    {
        WriteFullHeader(output, platform, dataPath);
        await WriteAppHealth(output, dataPath, cancellationToken);

        if (OperatingSystem.IsWindows())
        {
            WriteWindowsServiceStatus(output, state);
        }

        if (platform.RunningInContainer)
        {
            WriteDockerHints(output);
        }

        await WriteRegistrationState(output, state, status, platform.RunningInContainer, cancellationToken);
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

        await WriteConnectivityProbes(output, state, status, cancellationToken);

        if (OperatingSystem.IsWindows())
        {
            await WriteWindowsUpdateProbes(output, cancellationToken);
        }

        await WriteRecentLogs(output, dataPath, cancellationToken);
    }

    private async Task RunFocusedAsync(
        TextWriter output,
        Platform platform,
        PlatformType platformType,
        string dataPath,
        RelayState? state,
        RelayStatus? status,
        CancellationToken cancellationToken)
    {
        WriteMinimalHeader(output);

        var issueCount = 0;
        var ingestHadNoData = false;

        issueCount += await FlushIfIssues(output, w => WriteAppHealth(w, dataPath, cancellationToken));

        if (OperatingSystem.IsWindows())
        {
            issueCount += await FlushWindowsServiceStatusIfIssues(output, state);
        }

        if (platform.RunningInContainer)
        {
            issueCount += await FlushIfIssues(output, w => WriteDockerHints(w));
        }

        issueCount += await FlushIfIssues(
            output,
            w => WriteRegistrationState(w, state, status, platform.RunningInContainer, cancellationToken));

        // Capture ingest separately so we can detect the specific "no data" condition,
        // which warrants showing the Network section as a fix hint.
        using (var ingestBuffer = new StringWriter())
        {
            await WriteIngestPipeline(ingestBuffer, cancellationToken);
            var ingestContent = ingestBuffer.ToString();
            if (ingestContent.Contains('⚠') || ingestContent.Contains('✗'))
            {
                output.Write(ingestContent);
                issueCount++;
            }

            ingestHadNoData = ingestContent.Contains("No syslog data received yet")
                || ingestContent.Contains("Last syslog activity was");
        }

        issueCount += await FlushIfIssues(output, w => WriteFailedFiles(w));
        issueCount += await FlushIfIssues(output, w => WriteFirewallHistory(w, cancellationToken));

        // Network section: only shown when the specific "no data received" condition fired,
        // since that's when the fix is to point the syslog sender at this address.
        if (ingestHadNoData)
        {
            if (!platform.RunningInContainer)
            {
                WriteNetworkAddresses(output, platformType);
            }
            else
            {
                WriteDockerNetworkHint(output);
            }
        }

        if (OperatingSystem.IsWindows())
        {
            issueCount += await FlushWindowsFirewallRulesIfIssues(output);
        }

        if (_options.FileWatcherEnabled)
        {
            issueCount += await FlushIfIssues(output, w => WriteDropFolder(w));
        }

        if (_options.TlsEnabled)
        {
            issueCount += await FlushIfIssues(output, w => WriteTlsStatus(w));
        }

        issueCount += await FlushIfIssues(
            output,
            w => WriteConnectivityProbes(w, state, status, cancellationToken));

        if (OperatingSystem.IsWindows())
        {
            issueCount += await FlushIfIssues(output, w => WriteWindowsUpdateProbes(w, cancellationToken));
        }

        issueCount += await FlushIfIssues(output, w => WriteRecentLogs(w, dataPath, cancellationToken));

        if (issueCount == 0)
        {
            output.WriteLine($"  {Tick}  All checks passed.");
            output.WriteLine();
        }

        output.WriteLine($"  Run with --full for a complete diagnostic report.");
        output.WriteLine();
    }

    /// <summary>
    /// Runs <paramref name="section"/> into a buffer. If the output contains a warning or error
    /// marker, flushes it to <paramref name="output"/> and returns 1; otherwise discards it and returns 0.
    /// </summary>
    private static async Task<int> FlushIfIssues(TextWriter output, Func<TextWriter, Task> section)
    {
        using var buffer = new StringWriter();
        await section(buffer);
        var content = buffer.ToString();
        if (content.Contains('⚠') || content.Contains('✗'))
        {
            output.Write(content);
            return 1;
        }

        return 0;
    }

    private static Task<int> FlushIfIssues(TextWriter output, Action<TextWriter> section)
    {
        using var buffer = new StringWriter();
        section(buffer);
        var content = buffer.ToString();
        if (content.Contains('⚠') || content.Contains('✗'))
        {
            output.Write(content);
            return Task.FromResult(1);
        }

        return Task.FromResult(0);
    }

    [SupportedOSPlatform("windows")]
    private static Task<int> FlushWindowsServiceStatusIfIssues(TextWriter output, RelayState? state)
    {
        using var buffer = new StringWriter();
        WriteWindowsServiceStatus(buffer, state);
        var content = buffer.ToString();
        if (content.Contains('⚠') || content.Contains('✗'))
        {
            output.Write(content);
            return Task.FromResult(1);
        }

        return Task.FromResult(0);
    }

    [SupportedOSPlatform("windows")]
    private async Task<int> FlushWindowsFirewallRulesIfIssues(TextWriter output)
    {
        using var buffer = new StringWriter();
        await WriteWindowsFirewallRules(buffer);
        var content = buffer.ToString();
        if (content.Contains('⚠') || content.Contains('✗'))
        {
            output.Write(content);
            return 1;
        }

        return 0;
    }

    private void WriteFullHeader(TextWriter writer, Platform platform, string dataPath)
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

    private void WriteMinimalHeader(TextWriter writer)
    {
        writer.WriteLine("╔══════════════════════════════════════════════════════════════╗");
        writer.WriteLine("║       CyberAlarm Secure Sensor — Diagnostics                 ║");
        writer.WriteLine("╚══════════════════════════════════════════════════════════════╝");
        writer.WriteLine();
        writer.WriteLine($"  Version    : {_options.BuildVersion}");
        writer.WriteLine($"  Time (UTC) : {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}");
        writer.WriteLine();
    }

    private async Task WriteAppHealth(TextWriter writer, string dataPath, CancellationToken cancellationToken)
    {
        WriteSectionHeader(writer, "App Health");

        var healthCheckPath = Path.Combine(dataPath, "healthcheck.json");

        if (!File.Exists(healthCheckPath))
        {
            WriteHealthCheckMissingHint(writer);
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

        WriteHealthEntries(writer, healthData);
    }

    private void WriteHealthCheckMissingHint(TextWriter writer)
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
    }

    private static void WriteHealthEntries(TextWriter writer, Dictionary<string, JsonElement?> healthData)
    {
        var anyUnhealthy = false;
        foreach (var (service, entry) in healthData)
        {
            if (entry is null)
            {
                writer.WriteLine($"  {Warn}  {service,-35} Not yet reported");
                anyUnhealthy = true;
                continue;
            }

            var statusStr = GetHealthStatusString(entry.Value);
            if (statusStr == "Healthy")
            {
                continue;
            }

            var timestamp = entry.Value.TryGetProperty("Timestamp", out var tsProp)
                ? tsProp.GetDateTime()
                : (DateTime?)null;
            var tsDisplay = timestamp.HasValue ? timestamp.Value.ToString("HH:mm:ss") + " UTC" : string.Empty;
            writer.WriteLine($"  {Warn}  {service,-35} {statusStr ?? "Unknown",-12} {tsDisplay}");
            anyUnhealthy = true;
        }

        if (!anyUnhealthy)
        {
            writer.WriteLine($"  {Tick}  All services healthy.");
        }

        writer.WriteLine();
    }

    // Status is serialised as an integer (0=Healthy, 1=Degraded, 2=Unhealthy) or as a string
    private static string? GetHealthStatusString(JsonElement entry)
    {
        if (!entry.TryGetProperty("Status", out var sProp))
        {
            return null;
        }

        return sProp.ValueKind == JsonValueKind.Number
            ? sProp.GetInt32() switch { 0 => "Healthy", 1 => "Degraded", 2 => "Unhealthy", var n => $"Status({n})" }
            : sProp.GetString();
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
        TextWriter writer, RelayState? state, RelayStatus? status, bool runningInContainer, CancellationToken cancellationToken)
    {
        WriteSectionHeader(writer, "Registration & Upload State");

        if (state is null)
        {
            writer.WriteLine($"  {Warn}  state.json not found — service has not completed first-run initialisation.");
            writer.WriteLine($"     Check the service is running and review logs for initialisation errors.");
            writer.WriteLine();
            return;
        }

        var effectiveToken = !string.IsNullOrEmpty(_options.Bucket)
            ? _options.RegistrationToken
            : state.RegistrationToken ?? string.Empty;
        var relayId = RegistrationToken.GetRelayId(effectiveToken);

        writer.WriteLine($"  Registered        : {(state.IsRegistered ? Tick + "  Yes" : Warn + "  No")}");
        writer.WriteLine($"  Upload blocked    : {(state.IsUploadBlocked ? Warn + "  Yes" : Tick + "  No")}");
        writer.WriteLine($"  Uploads disabled  : {(status?.UploadsDisabled == true ? Warn + "  Yes (server-side flag)" : Tick + "  No")}");
        writer.WriteLine($"  Relay ID          : {(string.IsNullOrEmpty(relayId) ? Warn + "  (unknown — token not available)" : relayId)}");

        if (!state.IsRegistered)
        {
            WriteNotRegisteredSection(writer, runningInContainer);
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
            writer.WriteLine($"       1. Generate a new registration token in the CyberAlarm portal.");
            writer.WriteLine($"          (Tokens cannot be retrieved — you must create a new one.)");
            if (runningInContainer)
            {
                writer.WriteLine($"       2. Update REGISTRATION_TOKEN in your .env file and run:");
                writer.WriteLine($"            docker compose up -d");
            }
            else
            {
                writer.WriteLine($"       2. Update RegistrationToken in appsettings.json.");
                writer.WriteLine($"       3. Restart the 'CyberAlarm Syslog Relay' service.");
            }
        }

        if (status?.UploadsDisabled == true)
        {
            writer.WriteLine();
            writer.WriteLine($"  {Warn}  Uploads have been disabled by the server. Contact CyberAlarm support.");
        }

        writer.WriteLine();
    }

    private static void WriteNotRegisteredSection(TextWriter writer, bool runningInContainer)
    {
        writer.WriteLine();
        writer.WriteLine($"  {Warn}  The sensor is not registered.");
        writer.WriteLine($"     Generate a new registration token in the CyberAlarm portal and re-configure the sensor:");
        if (runningInContainer)
        {
            writer.WriteLine($"       1. Update REGISTRATION_TOKEN in your .env file.");
            writer.WriteLine($"       2. Run: docker compose up -d");
        }
        else
        {
            writer.WriteLine($"       1. Update RegistrationToken in appsettings.json.");
            writer.WriteLine($"       2. Restart the 'CyberAlarm Syslog Relay' service.");
        }
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
        {
            await WriteParseStats(writer, logDataFiles[0], cancellationToken);
        }

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
            var appLogPath = Path.Combine(_fileManager.GetDataPath(), "logs");
            var appLogFiles = Directory.Exists(appLogPath) && Directory.GetFiles(appLogPath, LogFilePattern).Length > 0;

            if (!appLogFiles)
            {
                writer.WriteLine($"  {Warn}  No syslog data and no log files found. The service may not have started yet.");
            }
            else
            {
                writer.WriteLine($"  {Warn}  No syslog data received yet. Ensure your syslog sender is pointed at the addresses in the Network section.");
            }
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
            [StatusSuccess] = 0,
            [StatusUnableToPatternMatch] = 0,
            [StatusUnableToParse] = 0,
            [StatusLocalOnlyEvent] = 0,
            [StatusIgnored] = 0,
        };

        var total = await CountParsedEventsAsync(writer, logFilePath, counts, cancellationToken);
        if (total == 0)
        {
            return;
        }

        WriteParseStatsSummary(writer, counts, total);
    }

    private static async Task<int> CountParsedEventsAsync(
        TextWriter writer, string logFilePath, Dictionary<string, int> counts, CancellationToken cancellationToken)
    {
        const int MaxSample = 500;
        var total = 0;

        try
        {
            await using var stream = File.OpenRead(logFilePath);
            using var reader = new StreamReader(stream);

            while (total < MaxSample)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var line = await reader.ReadLineAsync(cancellationToken);
                if (line is null)
                {
                    break;
                }

                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                TryCountValidationStatus(line, counts, ref total);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            writer.WriteLine($"  (Could not sample parse stats: {ex.Message})");
            return 0;
        }

        return total;
    }

    private static void TryCountValidationStatus(string line, Dictionary<string, int> counts, ref int total)
    {
        try
        {
            using var doc = JsonDocument.Parse(line);
            if (!doc.RootElement.TryGetProperty("ValidationStatus", out var vs))
            {
                return;
            }

            var key = vs.GetString() ?? string.Empty;
            if (counts.TryGetValue(key, out var existing))
            {
                counts[key] = existing + 1;
            }

            total++;
        }
        catch (JsonException)
        {
            // skip malformed lines
        }
    }

    private static void WriteParseStatsSummary(TextWriter writer, Dictionary<string, int> counts, int total)
    {
        writer.WriteLine($"  Parse stats (sample of {total} events from newest log file):");
        writer.WriteLine($"    {StatusSuccess,-25} {counts[StatusSuccess],4}   will be uploaded");

        if (counts[StatusUnableToPatternMatch] > 0)
        {
            writer.WriteLine($"    {StatusUnableToPatternMatch,-25} {counts[StatusUnableToPatternMatch],4}   no parser matched — device may not be supported");
        }

        if (counts[StatusUnableToParse] > 0)
        {
            writer.WriteLine($"    {StatusUnableToParse,-25} {counts[StatusUnableToParse],4}   parser matched but failed — check firmware version");
        }

        if (counts[StatusLocalOnlyEvent] > 0)
        {
            writer.WriteLine($"    {StatusLocalOnlyEvent,-25} {counts[StatusLocalOnlyEvent],4}   filtered as local/private traffic (not uploaded)");
        }

        if (counts[StatusIgnored] > 0)
        {
            writer.WriteLine($"    {StatusIgnored,-25} {counts[StatusIgnored],4}   matched ignore rules");
        }

        var unparseable = counts[StatusUnableToPatternMatch] + counts[StatusUnableToParse];
        if ((double)unparseable / total > 0.5)
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

        if (files.Count == 0)
        {
            return;
        }

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
                {
                    writer.WriteLine($"  {Tick}  {name,-50} {lines.Length,4} lines  valid NDJSON");
                }
                else
                {
                    writer.WriteLine($"  {Warn}  {name,-50} corrupted — {parseError}");
                }
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
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

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

        var sourceEntries = LoadSourceGroupEntries();
        WriteSourceGroupTable(writer, sourceEntries);
        writer.WriteLine();

        var connections = await ScanLogsForConnections(cancellationToken);
        WriteTcpConnectionTable(writer, connections);

        writer.WriteLine();
    }

    private List<(string Source, DateTime LastActive)> LoadSourceGroupEntries()
    {
        var sourceGroupFolder = _fileManager.GetSourceGroupFolder();
        var sourceEntries = new List<(string Source, DateTime LastActive)>();

        if (!Directory.Exists(sourceGroupFolder))
        {
            return sourceEntries;
        }

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

        return sourceEntries;
    }

    private void WriteSourceGroupTable(TextWriter writer, List<(string Source, DateTime LastActive)> sourceEntries)
    {
        if (sourceEntries.Count == 0)
        {
            writer.WriteLine($"  No processed syslog sources on record yet.");
            return;
        }

        var staleThreshold = TimeSpan.FromMinutes(_scheduleOptions.UploadIntervalInMinutes * 2);
        writer.WriteLine("  Known syslog sources (from processed data — survives log rotation):");
        writer.WriteLine($"  {"Source",-35} {"Last Active (UTC)",-22} Status");
        writer.WriteLine($"  {"─────────────────────────────────",-35} {"────────────────────",-22} ──────────────────────");

        foreach (var (source, lastActive) in sourceEntries.OrderByDescending(e => e.LastActive))
        {
            var age = DateTime.UtcNow - lastActive;
            var statusMark = age > staleThreshold ? $"{Warn} no activity in {FormatAge(age)}" : Tick;
            writer.WriteLine($"  {source,-35} {lastActive:yyyy-MM-dd HH:mm}        {statusMark}");
        }
    }

    private static void WriteTcpConnectionTable(
        TextWriter writer, List<(string Ip, DateTime? LastConnected, DateTime? LastDisconnected)> connections)
    {
        if (connections.Count == 0)
        {
            writer.WriteLine($"  No TCP connection events found in recent logs.");
            writer.WriteLine($"  Connection events are logged at Debug level. To enable:");
            writer.WriteLine($"    Add to appsettings: \"Serilog\": {{ \"MinimumLevel\": {{ \"Default\": \"Debug\" }} }}");
            return;
        }

        writer.WriteLine("  TCP connection events (from recent CLEF logs):");
        writer.WriteLine($"  {"Client IP",-22} {"Last Connected (UTC)",-22} {"Last Disconnected (UTC)",-24} Status");
        writer.WriteLine($"  {"─────────────────────",-22} {"────────────────────",-22} {"──────────────────────",-24} ──────");

        foreach (var (ip, lastConnected, lastDisconnected) in connections.OrderByDescending(c => c.LastConnected))
        {
            var connStr = lastConnected.HasValue ? lastConnected.Value.ToString("yyyy-MM-dd HH:mm") : "—";
            var discStr = lastDisconnected.HasValue ? lastDisconnected.Value.ToString("yyyy-MM-dd HH:mm") : "—";
            var connStatus = lastConnected > lastDisconnected ? "Active" : "Disconnected";
            writer.WriteLine($"  {ip,-22} {connStr,-22} {discStr,-24} {connStatus}");
        }
    }

    private async Task<List<(string Ip, DateTime? LastConnected, DateTime? LastDisconnected)>> ScanLogsForConnections(
        CancellationToken cancellationToken)
    {
        var logsPath = Path.Combine(_fileManager.GetDataPath(), "logs");
        if (!Directory.Exists(logsPath))
        {
            return [];
        }

        var logFiles = Directory.GetFiles(logsPath, LogFilePattern).OrderByDescending(f => f).Take(3);
        var connected = new Dictionary<string, DateTime>(StringComparer.Ordinal);
        var disconnected = new Dictionary<string, DateTime>(StringComparer.Ordinal);

        foreach (var file in logFiles)
        {
            await ScanLogFileForConnections(file, connected, disconnected, cancellationToken);
        }

        var allIps = connected.Keys.Union(disconnected.Keys, StringComparer.Ordinal).ToHashSet();
        return [.. allIps.Select(ip => (
            ip,
            connected.TryGetValue(ip, out var c) ? (DateTime?)c : null,
            disconnected.TryGetValue(ip, out var d) ? (DateTime?)d : null))];
    }

    private static async Task ScanLogFileForConnections(
        string file,
        Dictionary<string, DateTime> connected,
        Dictionary<string, DateTime> disconnected,
        CancellationToken cancellationToken)
    {
        try
        {
            await using var stream = File.OpenRead(file);
            using var reader = new StreamReader(stream);

            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var line = await reader.ReadLineAsync(cancellationToken);
                if (line is null)
                {
                    break;
                }

                if (!string.IsNullOrWhiteSpace(line))
                {
                    ProcessConnectionLogLine(line, connected, disconnected);
                }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _ = ex;
        }
    }

    private static void ProcessConnectionLogLine(
        string line,
        Dictionary<string, DateTime> connected,
        Dictionary<string, DateTime> disconnected)
    {
        try
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;

            if (!root.TryGetProperty("@mt", out var mtProp))
            {
                return;
            }

            var template = mtProp.GetString();
            if (template is null)
            {
                return;
            }

            var isConnect = template.Contains("[{Client}] connected.", StringComparison.Ordinal);
            var isDisconnect = template.Contains("[{Client}] disconnected.", StringComparison.Ordinal);
            if (!isConnect && !isDisconnect)
            {
                return;
            }

            if (!root.TryGetProperty("Client", out var clientProp))
            {
                return;
            }

            var ip = ParseClientIp(clientProp.GetString() ?? string.Empty);
            if (ip is null)
            {
                return;
            }

            var timestamp = root.TryGetProperty("@t", out var tsProp)
                && DateTime.TryParse(tsProp.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed)
                    ? parsed
                    : DateTime.UtcNow;

            var dict = isConnect ? connected : disconnected;
            if (!dict.TryGetValue(ip, out var prev) || timestamp > prev)
            {
                dict[ip] = timestamp;
            }
        }
        catch (JsonException)
        {
            // skip malformed line
        }
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
            {
                ports += $", TLS {_options.TlsPort}";
            }

            writer.WriteLine($"    {ip,-22} {ports}");
        }

        if (addresses.Count == 0)
        {
            writer.WriteLine($"  {Warn}  No network addresses found.");
        }

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
            writer.WriteLine($"  {Tick}  Port {_options.TcpPort} is in use by this service (expected).");
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

    [SupportedOSPlatform("windows")]
    private static bool CheckPortConflict(int port)
    {
        // Try to bind the port. If it succeeds, nothing is using it.
        try
        {
            var listener = new TcpListener(IPAddress.Any, port);
            listener.Start();
            listener.Stop();
            return false;
        }
        catch (SocketException)
        {
            // Port is occupied. If the relay service is running, it is the expected owner.
            try
            {
                using var sc = new System.ServiceProcess.ServiceController(ServiceName);
                return sc.Status != System.ServiceProcess.ServiceControllerStatus.Running;
            }
            catch
            {
                // Cannot determine service status — assume conflict.
                return true;
            }
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
            {
                writer.WriteLine($"     New-Item -ItemType Directory -Path \"{path}\"");
            }
            else
            {
                writer.WriteLine($"     mkdir -p \"{path}\"");
            }
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
        {
            writer.WriteLine($"  {Warn}  Certificate file not found — TLS listener will fail to start.");
        }
        else
        {
            writer.WriteLine($"  {Tick}  Certificate file exists.");
        }

        if (!_options.AllowPlaintextListenersWhenTlsEnabled)
        {
            writer.WriteLine();
            writer.WriteLine($"  ℹ  Plaintext TCP/UDP on port {_options.TcpPort} are DISABLED (AllowPlaintextListenersWhenTlsEnabled=false).");
            writer.WriteLine($"     Syslog senders must use TLS on port {_options.TlsPort}.");
        }

        writer.WriteLine();
    }

    private async Task WriteWindowsUpdateProbes(TextWriter writer, CancellationToken cancellationToken)
    {
        var enabled = _configuration.GetValue("WindowsUpdate:Enabled", true);
        if (!enabled)
        {
            return;
        }

        WriteSectionHeader(writer, "Windows Auto-Update Connectivity");

        var repoUrl = _configuration["WindowsUpdate:RepositoryUrl"];
        if (!string.IsNullOrWhiteSpace(repoUrl))
        {
            writer.WriteLine($"  Update source: {repoUrl}");
            writer.WriteLine();
        }

        var apiOk = await ProbeAndWrite(writer, "api.github.com", 443, "HTTPS api.github.com:443  (release metadata)", cancellationToken);
        var assetsOk = await ProbeAndWrite(writer, "objects.githubusercontent.com", 443, "HTTPS objects.githubusercontent.com:443  (update assets)", cancellationToken);

        if (!apiOk || !assetsOk)
        {
            writer.WriteLine();
            writer.WriteLine($"  {Warn}  GitHub connectivity check failed. Auto-updates will not work until");
            writer.WriteLine($"     these hosts are reachable on port 443/TCP.");
            writer.WriteLine();
            writer.WriteLine($"  Test with PowerShell:");
            writer.WriteLine($"    Test-NetConnection api.github.com -Port 443");
            writer.WriteLine($"    Test-NetConnection objects.githubusercontent.com -Port 443");
        }
        else
        {
            writer.WriteLine();
            writer.WriteLine($"  {Tick}  GitHub update connectivity OK.");
        }

        writer.WriteLine();
    }

    private async Task WriteConnectivityProbes(TextWriter writer, RelayState? state, RelayStatus? status, CancellationToken cancellationToken)
    {
        WriteSectionHeader(writer, "Connectivity Probes");

        if (status is null)
        {
            writer.WriteLine($"  {Warn}  status.json not found — upload destination unknown. Checking API only:");
            writer.WriteLine();
            await ProbeAndWrite(writer, ExtractHost(_options.ApiBaseUrl), 443, $"API ({ExtractHost(_options.ApiBaseUrl)}:443)", cancellationToken);
            await ProbeHttpGet(writer, _options.StatusEndpoint, "API status endpoint", cancellationToken);
            writer.WriteLine();
            writer.WriteLine($"  Once the service has initialised, status.json will be created and");
            writer.WriteLine($"  the full upload path can be probed.");
            writer.WriteLine();
            return;
        }

        // Prefer the live config token; fall back to the persisted token in state.json.
        // The fallback handles `docker run --rm ... --diagnostics` without the env var set.
        var effectiveToken = !string.IsNullOrEmpty(_options.Bucket)
            ? _options.RegistrationToken
            : state?.RegistrationToken ?? string.Empty;
        var bucket = RegistrationToken.GetBucket(effectiveToken);

        if (!status.StorageAccounts.TryGetValue(bucket, out var storageAccountName)
            || string.IsNullOrEmpty(storageAccountName))
        {
            writer.WriteLine($"  {Warn}  Could not determine upload host — bucket '{bucket}' not found in status.json.");
            writer.WriteLine($"     This may indicate a corrupted registration. Contact support.");
            writer.WriteLine();
            await ProbeAndWrite(writer, ExtractHost(_options.ApiBaseUrl), 443, $"API ({ExtractHost(_options.ApiBaseUrl)}:443)", cancellationToken);
            await ProbeHttpGet(writer, _options.StatusEndpoint, "API status endpoint", cancellationToken);
            writer.WriteLine();
            return;
        }

        var storageHost = $"{storageAccountName}.blob.core.windows.net";

        var sftpOk = await ProbeAndWrite(writer, storageHost, 22, $"SFTP  {storageHost}:22  (primary upload)", cancellationToken);
        var httpsOk = await ProbeAndWrite(writer, storageHost, 443, $"HTTPS {storageHost}:443  (fallback upload — step 2)", cancellationToken);
        var apiOk = await ProbeAndWrite(writer, ExtractHost(_options.ApiBaseUrl), 443, $"HTTPS {ExtractHost(_options.ApiBaseUrl)}:443  (API / fallback — step 1)", cancellationToken);
        await ProbeHttpGet(writer, _options.StatusEndpoint, "API status endpoint", cancellationToken);

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

    private async Task ProbeHttpGet(TextWriter writer, string url, string label, CancellationToken cancellationToken)
    {
        writer.Write($"  {Arrow} {label,-62} ");
        try
        {
            using var client = _httpClientFactory.CreateClient("diagnostics");
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            var response = await client.SendAsync(
                new HttpRequestMessage(HttpMethod.Get, url), cts.Token);
            if (response.StatusCode == System.Net.HttpStatusCode.OK)
            {
                writer.WriteLine($"{Tick} HTTP 200");
            }
            else
            {
                writer.WriteLine($"{Warn} HTTP {(int)response.StatusCode} (unexpected — API may be unavailable)");
            }
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

        var logFiles = Directory.GetFiles(logsPath, LogFilePattern).OrderByDescending(f => f).Take(3).ToList();

        if (logFiles.Count == 0)
        {
            writer.WriteLine($"  No log files found. Service may not have generated any logs yet.");
            writer.WriteLine();
            return;
        }

        var (grouped, total24H) = await ReadLogGroupingAsync(logFiles, cancellationToken);

        writer.WriteLine($"  Errors/Warnings in last 24 h: {total24H}");
        writer.WriteLine();
        WriteLogGroupTable(writer, grouped);
        writer.WriteLine();
    }

    private static async Task<(Dictionary<string, (int Count, DateTime MostRecent, string Level)> Grouped, int Total24H)>
        ReadLogGroupingAsync(List<string> logFiles, CancellationToken cancellationToken)
    {
        var grouped = new Dictionary<string, (int Count, DateTime MostRecent, string Level)>(StringComparer.Ordinal);
        var total24H = 0;
        var totalRead = 0;
        const int MaxLines = 500;

        foreach (var file in logFiles)
        {
            if (totalRead >= MaxLines)
            {
                break;
            }

            var (linesRead, within24H) = await ReadLogFileAsync(file, grouped, MaxLines - totalRead, cancellationToken);
            totalRead += linesRead;
            total24H += within24H;
        }

        return (grouped, total24H);
    }

    private static async Task<(int LinesRead, int Within24H)> ReadLogFileAsync(
        string file,
        Dictionary<string, (int Count, DateTime MostRecent, string Level)> grouped,
        int maxLines,
        CancellationToken cancellationToken)
    {
        var linesRead = 0;
        var within24H = 0;
        var cutoff = DateTime.UtcNow.AddHours(-24);

        try
        {
            await using var stream = File.OpenRead(file);
            using var reader = new StreamReader(stream);

            while (linesRead < maxLines)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var line = await reader.ReadLineAsync(cancellationToken);
                if (line is null)
                {
                    break;
                }

                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                linesRead++;
                within24H += ProcessRecentLogLine(line, grouped, cutoff);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _ = ex;
        }

        return (linesRead, within24H);
    }

    private static int ProcessRecentLogLine(
        string line,
        Dictionary<string, (int Count, DateTime MostRecent, string Level)> grouped,
        DateTime cutoff)
    {
        try
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;

            if (!root.TryGetProperty("@l", out var levelProp))
            {
                return 0;
            }

            var level = levelProp.GetString() ?? string.Empty;
            if (level is not ("Warning" or "Error" or "Fatal"))
            {
                return 0;
            }

            if (!root.TryGetProperty("@mt", out var mtProp))
            {
                return 0;
            }

            var template = mtProp.GetString() ?? string.Empty;

            var timestamp = root.TryGetProperty("@t", out var tsProp)
                && DateTime.TryParse(tsProp.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsedTs)
                    ? parsedTs
                    : DateTime.UtcNow;

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

            return timestamp >= cutoff ? 1 : 0;
        }
        catch (JsonException)
        {
            return 0;
        }
    }

    private static void WriteLogGroupTable(
        TextWriter writer, Dictionary<string, (int Count, DateTime MostRecent, string Level)> grouped)
    {
        if (grouped.Count == 0)
        {
            writer.WriteLine($"  {Tick}  No warnings or errors in recent logs.");
            return;
        }

        writer.WriteLine($"  {"Count",-7} {"Level",-6} {"Most Recent (UTC)",-22} Message Template");
        writer.WriteLine($"  {"─────",-7} {"─────",-6} {"──────────────────",-22} {"────────────────────────────────────────────────────────────"}");

        foreach (var (template, (count, mostRecent, level)) in grouped.OrderByDescending(g => g.Value.Count).Take(15))
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

    private async Task<LogEntry?> FindUploadBlockedLogEntry(CancellationToken cancellationToken)
    {
        var logsPath = Path.Combine(_fileManager.GetDataPath(), "logs");
        if (!Directory.Exists(logsPath))
        {
            return null;
        }

        foreach (var file in Directory.GetFiles(logsPath, LogFilePattern).OrderByDescending(f => f))
        {
            var match = await ScanLogFileForBlockingEntry(file, cancellationToken);
            if (match is not null)
            {
                return match;
            }
        }

        return null;
    }

    private static async Task<LogEntry?> ScanLogFileForBlockingEntry(string file, CancellationToken cancellationToken)
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
                if (line is null)
                {
                    break;
                }

                if (!string.IsNullOrWhiteSpace(line))
                {
                    var entry = TryMatchBlockingLogLine(line);
                    if (entry is not null)
                    {
                        lastMatch = entry;
                    }
                }
            }

            return lastMatch;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _ = ex;
            return null;
        }
    }

    private static LogEntry? TryMatchBlockingLogLine(string line)
    {
        try
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;

            if (!root.TryGetProperty("@l", out var lv) || lv.GetString() is not "Fatal")
            {
                return null;
            }

            if (!root.TryGetProperty("@mt", out var mt))
            {
                return null;
            }

            var template = mt.GetString();
            if (template is null)
            {
                return null;
            }

            if (!CriticalPatterns.Any(p => template.Contains(p, StringComparison.OrdinalIgnoreCase)))
            {
                return null;
            }

            var ts = root.TryGetProperty("@t", out var tsProp)
                && DateTime.TryParse(tsProp.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed)
                    ? parsed
                    : DateTime.UtcNow;

            return new LogEntry(ts, template);
        }
        catch
        {
            return null;
        }
    }

    private static string FormatAge(TimeSpan age)
    {
        if (age.TotalDays >= 1)
        {
            return $"{(int)age.TotalDays} day{((int)age.TotalDays == 1 ? string.Empty : "s")}";
        }

        if (age.TotalHours >= 1)
        {
            return $"{(int)age.TotalHours} hour{((int)age.TotalHours == 1 ? string.Empty : "s")}";
        }

        return $"{(int)age.TotalMinutes} minute{((int)age.TotalMinutes == 1 ? string.Empty : "s")}";
    }

    private static string ExtractHost(string url)
    {
        try
        {
            return new Uri(url).Host;
        }
        catch
        {
            return url;
        }
    }

    private static void WriteSectionHeader(TextWriter writer, string title)
    {
        var dashes = new string('─', Math.Max(0, 64 - title.Length - 4));
        writer.WriteLine($"── {title} {dashes}");
    }

    private sealed record LogEntry(DateTime Timestamp, string Message);
}
