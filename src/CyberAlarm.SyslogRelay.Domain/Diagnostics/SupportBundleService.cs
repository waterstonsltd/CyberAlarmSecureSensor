using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using CyberAlarm.SyslogRelay.Domain.Registration;
using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Domain.State;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Diagnostics;

public sealed partial class SupportBundleService(
    IFileManager fileManager,
    IPlatformService platformService,
    DiagnosticsService diagnosticsService,
    IOptions<RelayOptions> relayOptions)
{
    private readonly IFileManager _fileManager = fileManager;
    private readonly IPlatformService _platformService = platformService;
    private readonly DiagnosticsService _diagnosticsService = diagnosticsService;
    private readonly RelayOptions _options = relayOptions.Value;

    public async Task<string> CreateBundleAsync(CancellationToken cancellationToken)
    {
        var timestamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss");
        var dataPath = _fileManager.GetDataPath();

        var platform = _platformService.GetPlatform();
        if (platform.RunningInContainer && !Directory.Exists(dataPath) && !Directory.Exists("/opt/cyberalarm"))
        {
            throw new InvalidOperationException(
                "Running in Docker but no data directory is accessible.\n\n" +
                "Run the support bundle using docker exec on the running container:\n\n" +
                "  docker exec syslog-relay ./CyberAlarm.SyslogRelay.ConsoleApp --support-bundle\n\n" +
                "Or use docker run with the install directory mounted for a fuller bundle:\n\n" +
                "  docker run --rm \\\n" +
                "    -v /opt/cyberalarm:/opt/cyberalarm:ro \\\n" +
                "    -v /opt/cyberalarm/data:/var/lib/syslog-relay:ro \\\n" +
                "    -v /tmp:/tmp \\\n" +
                "    ghcr.io/waterstonsltd/cyberalarm-securesensor:stable \\\n" +
                "    --support-bundle");
        }

        var effectiveToken = !string.IsNullOrEmpty(_options.Bucket)
            ? _options.RegistrationToken
            : (await _fileManager.DeserialiseFromFileAsync<RelayState>(
                Path.Combine(dataPath, "state.json"), cancellationToken))?.RegistrationToken ?? string.Empty;
        var relayId = RegistrationToken.GetRelayId(effectiveToken);
        var relayIdPart = string.IsNullOrEmpty(relayId) ? string.Empty : $"{relayId}-";

        var zipPath = Path.Combine(Path.GetTempPath(), $"cyberalarm-support-{relayIdPart}{timestamp}.zip");

        await using var zipStream = new FileStream(zipPath, FileMode.Create, FileAccess.Write);
        using var archive = new ZipArchive(zipStream, ZipArchiveMode.Create, leaveOpen: false);

        // diagnostics.txt
        await AddDiagnosticsText(archive, cancellationToken);

        // CLEF application log files
        var appLogsPath = Path.Combine(dataPath, "logs");
        if (Directory.Exists(appLogsPath))
        {
            foreach (var logFile in Directory.GetFiles(appLogsPath, "relay-*.json"))
            {
                AddFileToZip(archive, logFile, $"logs/{Path.GetFileName(logFile)}");
            }
        }

        // Sample of newest .tmp/logs/ NDJSON pipeline file
        await AddTmpLogsSample(archive, cancellationToken);

        // File counts per .tmp/ subfolder
        await AddFileCounts(archive, cancellationToken);

        // key.der existence check (never include the key itself)
        await AddKeyExistence(archive, dataPath, cancellationToken);

        // state.json with token redacted
        await AddRedactedState(archive, dataPath, cancellationToken);

        // status.json as-is
        AddOptionalFile(archive, Path.Combine(dataPath, "status.json"), "status.json");

        // healthcheck.json as-is
        AddOptionalFile(archive, Path.Combine(dataPath, "healthcheck.json"), "healthcheck.json");

        // appsettings files with token redacted
        await AddRedactedAppsettings(archive, dataPath, cancellationToken);

        // Docker deployment config (.env redacted, docker-compose.yml) — only when install dir is mounted
        if (platform.RunningInContainer && Directory.Exists("/opt/cyberalarm"))
        {
            await AddDockerDeploymentConfig(archive, cancellationToken);
        }

        // system-info.txt
        await AddSystemInfo(archive, dataPath, cancellationToken);

        return zipPath;
    }

    private async Task AddDiagnosticsText(ZipArchive archive, CancellationToken cancellationToken)
    {
        using var sw = new StringWriter();
        await _diagnosticsService.RunAsync(sw, verbose: true, cancellationToken);
        var entry = archive.CreateEntry("diagnostics.txt", CompressionLevel.Optimal);
        await using var entryStream = await entry.OpenAsync(cancellationToken);
        await using var writer = new StreamWriter(entryStream, Encoding.UTF8);
        await writer.WriteAsync(sw.ToString());
    }

    private async Task AddTmpLogsSample(ZipArchive archive, CancellationToken cancellationToken)
    {
        var logsFolder = _fileManager.GetLogsFolder();
        if (!Directory.Exists(logsFolder))
        {
            return;
        }

        var newestFile = Directory.GetFiles(logsFolder)
            .OrderByDescending(f => File.GetLastWriteTimeUtc(f))
            .FirstOrDefault();

        if (newestFile is null)
        {
            return;
        }

        const int MaxLines = 200;
        var entry = archive.CreateEntry("tmp-logs-sample.ndjson", CompressionLevel.Optimal);
        await using var entryStream = await entry.OpenAsync(cancellationToken);
        await using var writer = new StreamWriter(entryStream, Encoding.UTF8);

        await using var fileStream = new FileStream(newestFile, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);
        using var reader = new StreamReader(fileStream);

        var linesWritten = 0;
        while (linesWritten < MaxLines)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var line = await reader.ReadLineAsync(cancellationToken);
            if (line is null)
            {
                break;
            }

            await writer.WriteLineAsync(line);
            linesWritten++;
        }
    }

    private async Task AddFileCounts(ZipArchive archive, CancellationToken cancellationToken)
    {
        var folders = new (string Label, string Path)[]
        {
            ("logs/",          _fileManager.GetLogsFolder()),
            ("processing/",    _fileManager.GetProcessingFolder()),
            ("source-groups/", _fileManager.GetSourceGroupFolder()),
            ("upload/",        _fileManager.GetUploadFolder()),
            ("failed/",        _fileManager.GetFailedFolder()),
            ("temporaryFiles/", _fileManager.GetTemporaryFolder()),
        };

        var entry = archive.CreateEntry("file-counts.txt", CompressionLevel.Optimal);
        await using var entryStream = await entry.OpenAsync(cancellationToken);
        await using var writer = new StreamWriter(entryStream, Encoding.UTF8);

        await writer.WriteLineAsync($"File counts as of {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
        await writer.WriteLineAsync(new string('─', 60));

        foreach (var (label, path) in folders)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!Directory.Exists(path))
            {
                await writer.WriteLineAsync($"  {label,-22}  (folder does not exist)");
                continue;
            }

            var files = Directory.GetFiles(path, "*", SearchOption.AllDirectories);
            var totalBytes = files.Sum(f => new FileInfo(f).Length);
            await writer.WriteLineAsync($"  {label,-22}  {files.Length,5} file(s)   {FormatBytes(totalBytes),10}");
        }
    }

    private static async Task AddKeyExistence(ZipArchive archive, string dataPath, CancellationToken cancellationToken)
    {
        var keyPath = Path.Combine(dataPath, "key.der");
        var exists = File.Exists(keyPath);

        var entry = archive.CreateEntry("key-exists.txt", CompressionLevel.Optimal);
        await using var entryStream = await entry.OpenAsync(cancellationToken);
        await using var writer = new StreamWriter(entryStream, Encoding.UTF8);
        await writer.WriteLineAsync($"key.der exists: {exists}");
        await writer.WriteLineAsync("(The private key itself is never included in support bundles.)");
        cancellationToken.ThrowIfCancellationRequested();
    }

    private async Task AddRedactedState(ZipArchive archive, string dataPath, CancellationToken cancellationToken)
    {
        var statePath = Path.Combine(dataPath, "state.json");
        if (!File.Exists(statePath))
        {
            return;
        }

        var state = await _fileManager.DeserialiseFromFileAsync<RelayState>(statePath, cancellationToken);
        if (state is null)
        {
            return;
        }

        var redacted = state with { RegistrationToken = "[REDACTED]" };

        var entry = archive.CreateEntry("state-redacted.json", CompressionLevel.Optimal);
        await using var entryStream = await entry.OpenAsync(cancellationToken);
        await JsonSerializer.SerializeAsync(entryStream, redacted, cancellationToken: cancellationToken);
    }

    private static void AddOptionalFile(ZipArchive archive, string filePath, string entryName)
    {
        if (!File.Exists(filePath))
        {
            return;
        }

        archive.CreateEntryFromFile(filePath, entryName, CompressionLevel.Optimal);
    }

    private static async Task AddRedactedAppsettings(ZipArchive archive, string dataPath, CancellationToken cancellationToken)
    {
        var candidates = new[]
        {
            (Path.Combine(AppContext.BaseDirectory, "appsettings.json"), "appsettings.json"),
            (Path.Combine(dataPath, "appsettings.windows.local.json"), "appsettings.windows.local.json"),
        };

        var combined = new StringBuilder();
        combined.AppendLine("// Merged appsettings (registration token redacted)");
        combined.AppendLine();

        var anyFound = false;
        foreach (var (path, label) in candidates)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!File.Exists(path))
            {
                continue;
            }

            combined.AppendLine($"// ── {label} ──────────────────────────────────────────────────");
            var content = await File.ReadAllTextAsync(path, cancellationToken);
            content = RedactRegistrationToken(content);
            combined.AppendLine(content);
            combined.AppendLine();
            anyFound = true;
        }

        if (!anyFound)
        {
            return;
        }

        var entry = archive.CreateEntry("appsettings-redacted.json", CompressionLevel.Optimal);
        await using var entryStream = await entry.OpenAsync(cancellationToken);
        await using var writer = new StreamWriter(entryStream, Encoding.UTF8);
        await writer.WriteAsync(combined.ToString());
    }

    private async Task AddSystemInfo(ZipArchive archive, string dataPath, CancellationToken cancellationToken)
    {
        var platform = _platformService.GetPlatform();
        var gcInfo = GC.GetGCMemoryInfo();

        var entry = archive.CreateEntry("system-info.txt", CompressionLevel.Optimal);
        await using var entryStream = await entry.OpenAsync(cancellationToken);
        await using var writer = new StreamWriter(entryStream, Encoding.UTF8);

        await writer.WriteLineAsync($"System Information — {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
        await writer.WriteLineAsync(new string('─', 60));
        await writer.WriteLineAsync($"OS                    : {platform.Os}");
        await writer.WriteLineAsync($"Runtime               : {platform.Runtime}");
        await writer.WriteLineAsync($"Architecture          : {platform.Architecture}");
        await writer.WriteLineAsync($"Docker                : {platform.RunningInContainer}");
        await writer.WriteLineAsync($"Sensor Version        : {_options.BuildVersion}");
        await writer.WriteLineAsync();
        await writer.WriteLineAsync("Memory:");
        await writer.WriteLineAsync($"  Available RAM       : {FormatBytes(gcInfo.TotalAvailableMemoryBytes)}");
        await writer.WriteLineAsync($"  Process working set : {FormatBytes(Environment.WorkingSet)}");
        await writer.WriteLineAsync($"  GC total memory     : {FormatBytes(GC.GetTotalMemory(false))}");
        await writer.WriteLineAsync();

        var pathRoot = Path.GetPathRoot(dataPath);
        if (!string.IsNullOrEmpty(pathRoot))
        {
            try
            {
                var drive = new DriveInfo(pathRoot);
                await writer.WriteLineAsync("Disk (data path drive):");
                await writer.WriteLineAsync($"  Total size          : {FormatBytes(drive.TotalSize)}");
                await writer.WriteLineAsync($"  Available free      : {FormatBytes(drive.AvailableFreeSpace)}");
            }
            catch (Exception ex)
            {
                await writer.WriteLineAsync($"Disk info unavailable: {ex.Message}");
            }
        }

        cancellationToken.ThrowIfCancellationRequested();
    }

    private static void AddFileToZip(ZipArchive archive, string filePath, string entryName)
    {
        try
        {
            archive.CreateEntryFromFile(filePath, entryName, CompressionLevel.Optimal);
        }
        catch (Exception)
        {
            // Skip files that cannot be read (e.g. locked by another process)
        }
    }

    private static async Task AddDockerDeploymentConfig(ZipArchive archive, CancellationToken cancellationToken)
    {
        const string installDir = "/opt/cyberalarm";

        var envPath = Path.Combine(installDir, ".env");
        if (File.Exists(envPath))
        {
            try
            {
                var content = await File.ReadAllTextAsync(envPath, cancellationToken);
                content = RedactEnvToken(content);
                var entry = archive.CreateEntry("docker-env-redacted.txt", CompressionLevel.Optimal);
                await using var entryStream = await entry.OpenAsync(cancellationToken);
                await using var writer = new StreamWriter(entryStream, Encoding.UTF8);
                await writer.WriteAsync(content);
            }
            catch (UnauthorizedAccessException)
            {
                // Skip files that cannot be read due to permissions
            }
        }

        AddOptionalFile(archive, Path.Combine(installDir, "docker-compose.yml"), "docker-compose.yml");
    }

    private static string RedactEnvToken(string envContent)
    {
        return EnvRegistrationTokenPattern().Replace(envContent, "REGISTRATION_TOKEN=[REDACTED]");
    }

    private static string RedactRegistrationToken(string json)
    {
        return RegistrationTokenPattern().Replace(json, "\"REGISTRATION_TOKEN\": \"[REDACTED]\"");
    }

    private static string FormatBytes(long bytes)
    {
        return bytes switch
        {
            >= 1_073_741_824 => $"{bytes / 1_073_741_824.0:F1} GB",
            >= 1_048_576 => $"{bytes / 1_048_576.0:F1} MB",
            >= 1_024 => $"{bytes / 1_024.0:F1} KB",
            _ => $"{bytes} B",
        };
    }

    [GeneratedRegex("\"REGISTRATION_TOKEN\"\\s*:\\s*\"[^\"]*\"", RegexOptions.IgnoreCase)]
    private static partial Regex RegistrationTokenPattern();

    [GeneratedRegex(@"REGISTRATION_TOKEN=[^\r\n]*", RegexOptions.IgnoreCase)]
    private static partial Regex EnvRegistrationTokenPattern();
}
