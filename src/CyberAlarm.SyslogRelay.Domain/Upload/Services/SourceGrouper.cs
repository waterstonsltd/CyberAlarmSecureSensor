using System.Diagnostics;
using CyberAlarm.SyslogRelay.Common.EventBundler.Models;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Domain.Upload.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Upload.Services;

/// <summary>
/// SourceGrouper service.
/// Groups Syslog events by "source" and writes them to the source group folder.
/// "Source" can either by the source IP or a sanitised filename part.
/// </summary>
/// <param name="fileManager">Used for file IO.</param>
/// <param name="logger">Used for logging.</param>
internal class SourceGrouper(
    IFileManager fileManager,
    IOptions<RelayOptions> options,
    ILogger<SourceGrouper> logger) : ISourceGrouper
{
    private readonly IFileManager _fileManager = fileManager;
    private readonly ILogger<SourceGrouper> _logger = logger;
    private readonly long _maxFileSizeBytes = options.Value.RawGroupedLogsMaxFileSizeBytes;
    private readonly List<TempFileInfo> _metaData = [];

    public async Task GroupLogsBySourceAsync(CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();

        var inputFolder = _fileManager.GetProcessingFolder();
        var outputFolder = _fileManager.GetSourceGroupFolder();
        var failedFolder = _fileManager.GetFailedFolder();
        var temporaryFolder = _fileManager.GetTemporaryFolder();

        var inputFiles = _fileManager.ListFilesInDirectory(inputFolder).ToList();
        var totalFiles = inputFiles.Count;
        _logger.LogInformation("Found {TotalFiles} files to group", totalFiles);

        Dictionary<string, TempFileInfo> files = new();

        int processedCount = 0;
        int failedCount = 0;
        const int progressInterval = 100; // Log progress every 100 files

        foreach (var file in inputFiles)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var parsedEvents = await _fileManager.DeserialiseFromNdjson<ParsedEvent>(file, cancellationToken);
                if (parsedEvents is not null)
                {
                    var ingestionGroups = parsedEvents.GroupBy(log => log.EventSource.IngestionMethod);
                    foreach (var ingestionGroup in ingestionGroups)
                    {
                        cancellationToken.ThrowIfCancellationRequested();

                        var sourceGroups = ingestionGroup.GroupBy(log => log.EventSource.GetSanitisedGroupKey());

                        foreach (var sourceGroup in sourceGroups)
                        {
                            cancellationToken.ThrowIfCancellationRequested();

                            var tempFileInfo = GetOutputFile(outputFolder, temporaryFolder, files, ingestionGroup.Key, sourceGroup.Key);
                            var (bundleEvents, eventCounters) = GetBundleEvents(sourceGroup);

                            await _fileManager.AppendAndSaveItemsAsNdjson(bundleEvents, tempFileInfo.TempFilePath, cancellationToken);
                            tempFileInfo.SourceFiles.Add(file);
                            tempFileInfo.EventCounters.Update(eventCounters);
                        }
                    }

                    processedCount++;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing file {File}: {ErrorMessage}", file, ex.Message);

                try
                {
                    var failedFilePath = Path.Combine(failedFolder, Path.GetFileName(file));
                    _fileManager.Move(file, failedFilePath);
                    _logger.LogInformation("Moved failed file to {FailedFilePath}", failedFilePath);
                }
                catch (Exception moveEx)
                {
                    _logger.LogError(moveEx, "Failed to move file {File} to failed folder: {ErrorMessage}", file, moveEx.Message);
                }

                failedCount++;
            }

            // Log progress at intervals
            if ((processedCount + failedCount) % progressInterval == 0)
            {
                _logger.LogInformation(
                    "Grouping progress: {Processed}/{Total} files processed ({PercentComplete:F1}%), {Failed} failed, elapsed time: {Elapsed}",
                    processedCount + failedCount,
                    totalFiles,
                    ((processedCount + failedCount) / (double)totalFiles) * 100,
                    failedCount,
                    stopwatch.Elapsed.ToString(@"hh\:mm\:ss"));
            }
        }

        // Finalize all remaining temp files
        foreach (var tempFileInfo in files.Values.Where(p => _fileManager.Exists(p.TempFilePath)))
        {
            FinalizeTempFile(tempFileInfo);
        }

        // Persist events metadata to file
        var eventsMetaData = _metaData.ToDictionary(x => Path.GetFileName(x.OutputFilePath), x => x.TotEventsMetaData());
        var eventsMetaDataFilePath = _fileManager.GetEventsMetaDataFilePath();
        await _fileManager.SerialiseToFileAsync(eventsMetaData, eventsMetaDataFilePath, cancellationToken);

        stopwatch.Stop();
        _logger.LogInformation(
            "Grouping complete: {Processed} files grouped successfully, {Failed} failed out of {Total} total in {Elapsed}",
            processedCount,
            failedCount,
            totalFiles,
            stopwatch.Elapsed.ToString(@"hh\:mm\:ss"));
    }

    private TempFileInfo GetOutputFile(string outputFolder, string temporaryFolder, Dictionary<string, TempFileInfo> files, IngestionMethod ingestionMethod, string source)
    {
        var ingestionKey = ingestionMethod.ToString().ToLowerInvariant();
        var fileKey = $"{ingestionKey}_{source}";

        TempFileInfo? tempFileInfo;
        if (!files.TryGetValue(fileKey, out tempFileInfo) ||
            (File.Exists(tempFileInfo.TempFilePath) && new FileInfo(tempFileInfo.TempFilePath).Length >= _maxFileSizeBytes))
        {
            // Finalize the previous temp file if it exists and has reached max size
            if (tempFileInfo != null && File.Exists(tempFileInfo.TempFilePath))
            {
                FinalizeTempFile(tempFileInfo);
            }

            // Generate temp and output filepaths
            var tempFileName = Path.Combine(temporaryFolder, $"{Guid.NewGuid()}.tmp");
            var outputFileName = Path.Combine(outputFolder, ingestionKey, source, $"{Guid.NewGuid()}.ndjson");

            // Create new temp file
            _fileManager.CreateEmptyFile(tempFileName);

            tempFileInfo = new TempFileInfo(tempFileName, outputFileName, ingestionKey, source);
            files[fileKey] = tempFileInfo;
            _metaData.Add(tempFileInfo);
        }

        return tempFileInfo;
    }

    private static (List<BundleEvent> Events, EventCounters EventCounters) GetBundleEvents(IEnumerable<ParsedEvent> events)
    {
        List<BundleEvent> bundleEvents = [];
        var totalEvents = 0;
        var unmatchedEvents = 0;
        var unparsedEvents = 0;
        var localOnlyEvents = 0;

        foreach (var @event in events)
        {
            totalEvents++;

            switch (@event.ValidationStatus)
            {
                case ValidationStatus.UnableToPatternMatch:
                    unmatchedEvents++;
                    break;

                case ValidationStatus.UnableToParse:
                    unparsedEvents++;
                    break;

                case ValidationStatus.LocalOnlyEvent:
                    localOnlyEvents++;
                    break;

                default:
                    bundleEvents.Add(new(
                        @event.Timestamp,
                        @event.RawData,
                        @event.PatternName,
                        @event.ParseResult));
                    break;
            }
        }

        return (bundleEvents, new(totalEvents, unmatchedEvents, unparsedEvents, localOnlyEvents));
    }

    /// <summary>
    /// Renames a temporary file to its final .log extension and deletes all source files that contributed to it.
    /// </summary>
    /// <param name="tempFileInfo">Information about the temporary file and its source files.</param>
    private void FinalizeTempFile(TempFileInfo tempFileInfo)
    {
        try
        {
            _fileManager.Move(tempFileInfo.TempFilePath, tempFileInfo.OutputFilePath);
            _logger.LogDebug("Finalized temporary file: {TempFile} -> {FinalFile}", tempFileInfo.TempFilePath, tempFileInfo.OutputFilePath);

            // Delete all source files that contributed to this temp file
            foreach (var sourceFile in tempFileInfo.SourceFiles.Distinct())
            {
                try
                {
                    if (_fileManager.Exists(sourceFile))
                    {
                        _fileManager.Delete(sourceFile);
                        _logger.LogDebug("Deleted source file: {SourceFile}", sourceFile);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to delete source file {SourceFile}: {ErrorMessage}", sourceFile, ex.Message);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to finalize temporary file {TempFile}: {ErrorMessage}", tempFileInfo.TempFilePath, ex.Message);
        }
    }

    /// <summary>
    /// Tracks temporary file information and the source files that contributed to it.
    /// </summary>
    private sealed class TempFileInfo(
        string tempFilePath,
        string outputFilePath,
        string ingestion,
        string source)
    {
        public string TempFilePath { get; } = tempFilePath;

        public string OutputFilePath { get; } = outputFilePath;

        public string Ingestion { get; } = ingestion;

        public string Source { get; } = source;

        public HashSet<string> SourceFiles { get; } = [];

        public EventCounters EventCounters { get; } = new();

        public EventsMetaData TotEventsMetaData() =>
            new(
                Ingestion,
                Source,
                EventCounters.TotalEvents,
                EventCounters.UnmatchedEvents,
                EventCounters.UnparsedEvents,
                EventCounters.LocalOnlyEvents);
    }

    private sealed class EventCounters(
        int totalEvents,
        int unmatchedEvents,
        int unparsedEvents,
        int localOnlyEvents)
    {
        public EventCounters()
            : this(0, 0, 0, 0)
        {
        }

        public int TotalEvents { get; private set; } = totalEvents;

        public int UnmatchedEvents { get; private set; } = unmatchedEvents;

        public int UnparsedEvents { get; private set; } = unparsedEvents;

        public int LocalOnlyEvents { get; private set; } = localOnlyEvents;

        public void Update(EventCounters eventCounters)
        {
            TotalEvents += eventCounters.TotalEvents;
            UnmatchedEvents += eventCounters.UnmatchedEvents;
            UnparsedEvents += eventCounters.UnparsedEvents;
            LocalOnlyEvents += eventCounters.LocalOnlyEvents;
        }
    }
}
