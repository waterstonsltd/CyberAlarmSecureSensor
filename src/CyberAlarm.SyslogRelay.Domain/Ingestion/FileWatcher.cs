using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.HealthCheck;
using CyberAlarm.SyslogRelay.Domain.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Ingestion;

public sealed class FileWatcher(
    IFileManager fileManager,
    IFileIngestionReader fileReader,
    IPeriodicOperation periodicOperation,
    IHealthCheckService healthCheckService,
    IOptions<RelayOptions> options,
    ILogger<FileWatcher> logger) : IDisposable
{
    public const string RootSource = "root";

    private readonly IFileManager _fileManager = fileManager;
    private readonly IFileIngestionReader _fileReader = fileReader;
    private readonly IPeriodicOperation _periodicOperation = periodicOperation;
    private readonly IHealthToken _healthToken = healthCheckService.GetHealthToken(nameof(FileWatcher));
    private readonly RelayOptions _options = options.Value;
    private readonly ILogger<FileWatcher> _logger = logger;

    private Func<SyslogEvent, CancellationToken, Task>? _ingestAction;

    public async Task StartAsync(Func<SyslogEvent, CancellationToken, Task> ingestAction, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(ingestAction);
        _ingestAction = ingestAction;

        if (!await ValidateDropPath(cancellationToken))
        {
            await StopAsync();
            return;
        }

        _logger.LogInformation("Starting file watcher.");
        _logger.LogInformation("File import raw export replay: {FileWatcherReplayRawExports}.", _options.FileWatcherReplayRawExports);
        if (_options.FileWatcherReplayRawExports)
        {
            _logger.LogInformation("Raw export replay is enabled. Replayed records use current processing and may upload historical events again.");
        }

        var settings = new PeriodicOperationSettings(
            TimeSpan.FromSeconds(_options.FileWatcherIntervalInSeconds),
            Ingest,
            nameof(FileWatcher),
            true);

        _periodicOperation.Start(settings, cancellationToken);

        await _healthToken.HealthyAsync(cancellationToken);
    }

    public async Task StopAsync()
    {
        _logger.LogInformation("Stopping file watcher.");
        await _periodicOperation.StopAsync();

        Dispose();
    }

    public void Dispose() => _periodicOperation?.Dispose();

    private async Task Ingest(CancellationToken cancellationToken)
    {
        await IngestFolder(_options.FileWatcherDropPath, RootSource, cancellationToken);

        var folders = _fileManager.ListDirectoryNamesInDirectory(_options.FileWatcherDropPath);
        foreach (var folder in folders)
        {
            var folderPath = Path.Combine(_options.FileWatcherDropPath, folder);
            await IngestFolder(folderPath, folder, cancellationToken);
        }
    }

    private async Task IngestFolder(string folderPath, string source, CancellationToken cancellationToken)
    {
        var files = _fileManager.ListFileNamesInDirectory(folderPath);
        _logger.LogDebug("Ingesting {FileCount} file(s) from folder '{Folder}'.", files.Count(), folderPath);

        foreach (var file in files)
        {
            var markedFile = MarkedFile.Create(file);
            if (markedFile.RetryCount >= _options.FileWatcherMaximumRetryCount)
            {
                _logger.LogWarning("Skipping file '{File}' in folder '{Folder}' as it exceeds maximum retry count '{MaxRetryCount}'.", file, folderPath, _options.FileWatcherMaximumRetryCount);
                continue;
            }

            var filePath = Path.Combine(folderPath, file);
            var markedFilePath = Path.Combine(folderPath, markedFile.Name);

            _logger.LogDebug("Renaming file '{File}' to '{MarkedFile}' in folder '{Folder}'.", file, markedFile, folderPath);
            _fileManager.Move(filePath, markedFilePath);

            var ingested = await IngestFile(markedFilePath, source, cancellationToken);
            if (!ingested)
            {
                continue;
            }

            cancellationToken.ThrowIfCancellationRequested();
            _logger.LogDebug("Deleting marked file '{MarkedFile}' from folder '{Folder}'.", markedFile, folderPath);
            _fileManager.Delete(markedFilePath);
        }
    }

    private async Task<bool> IngestFile(string filePath, string source, CancellationToken cancellationToken)
    {
        _logger.LogDebug("Ingesting file '{FilePath}' from source '{Source}'.", filePath, source);

        try
        {
            await foreach (var raw in _fileReader.ReadAsync(filePath, cancellationToken))
            {
                cancellationToken.ThrowIfCancellationRequested();
                await _ingestAction!.Invoke(SyslogEvent.FromFile(source, raw), cancellationToken);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Error when ingesting file '{FilePath}' from source '{Source}'.", filePath, source);
            return false;
        }

        return true;
    }

    private async Task<bool> ValidateDropPath(CancellationToken cancellationToken)
    {
        if (!_options.FileWatcherEnabled)
        {
            await _healthToken.UnregisterAsync(cancellationToken);

            _logger.LogInformation("File watcher is disabled.");
            return false;
        }

        if (string.IsNullOrWhiteSpace(_options.FileWatcherDropPath))
        {
            await _healthToken.UnhealthyAsync(cancellationToken);

            _logger.LogError("File watcher is enabled but no drop path is configured.");
            throw new InvalidOperationException("File watcher is enabled but no drop path is configured.");
        }

        if (!_fileManager.Exists(_options.FileWatcherDropPath))
        {
            await _healthToken.UnhealthyAsync(cancellationToken);

            _logger.LogError(
                "File watcher is enabled but drop path '{DropPath}' does not exist.",
                _options.FileWatcherDropPath);
            throw new InvalidOperationException("File watcher drop path does not exist.");
        }

        return true;
    }
}
