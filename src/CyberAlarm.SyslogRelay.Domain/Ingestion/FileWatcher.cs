using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Ingestion;

public sealed class FileWatcher(
    IFileManager fileManager,
    IPeriodicOperation periodicOperation,
    IOptions<RelayOptions> options,
    ILogger<FileWatcher> logger) : IDisposable
{
    public const string RootSource = "root";

    private readonly IFileManager _fileManager = fileManager;
    private readonly IPeriodicOperation _periodicOperation = periodicOperation;
    private readonly RelayOptions _options = options.Value;
    private readonly ILogger<FileWatcher> _logger = logger;

    private Func<SyslogEvent, CancellationToken, Task>? _ingestAction;

    public async Task StartAsync(Func<SyslogEvent, CancellationToken, Task> ingestAction, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(ingestAction);
        _ingestAction = ingestAction;

        if (!ValidateDropPath())
        {
            await StopAsync();
            return;
        }

        _logger.LogInformation("Starting file watcher.");
        _periodicOperation.Start(new(TimeSpan.FromSeconds(_options.FileWatcherIntervalInSeconds), Ingest, nameof(FileWatcher)), cancellationToken);
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

            _logger.LogDebug("Deleting marked file '{MarkedFile}' from folder '{Folder}'.", markedFile, folderPath);
            _fileManager.Delete(markedFilePath);
        }
    }

    private async Task<bool> IngestFile(string filePath, string source, CancellationToken cancellationToken)
    {
        _logger.LogDebug("Ingesting file '{FilePath}' from source '{Source}'.", filePath, source);

        try
        {
            using var stream = _fileManager.OpenStreamFromFile(filePath, cancellationToken);
            using var reader = new StreamReader(stream);

            while (!cancellationToken.IsCancellationRequested)
            {
                var line = await reader.ReadLineAsync(cancellationToken);
                if (line == null)
                {
                    break;
                }

                if (string.IsNullOrWhiteSpace(line.Trim()))
                {
                    continue;
                }

                await _ingestAction!.Invoke(SyslogEvent.FromFile(source, line), cancellationToken);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Error when ingesting file '{FilePath}' from source '{Source}'.", filePath, source);
            return false;
        }

        return true;
    }

    private bool ValidateDropPath()
    {
        if (string.IsNullOrWhiteSpace(_options.FileWatcherDropPath))
        {
            _logger.LogInformation("File watcher drop path is not configured.");
            return false;
        }

        if (!_fileManager.Exists(_options.FileWatcherDropPath))
        {
            _logger.LogError("File watcher drop path does not exist.");
            return false;
        }

        return true;
    }
}
