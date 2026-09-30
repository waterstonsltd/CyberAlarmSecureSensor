using System.Runtime.CompilerServices;
using CyberAlarm.SyslogRelay.Domain.Services;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Ingestion;

public sealed class RawExportIngestionReader(
    IFileManager fileManager,
    TimeProvider timeProvider,
    ILogger<RawExportIngestionReader> logger) : IFileIngestionReader
{
    public async IAsyncEnumerable<string> ReadAsync(string filePath, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var stream = fileManager.OpenStreamFromFile(filePath, cancellationToken);
        bool replay;
        var phaseStarted = timeProvider.GetTimestamp();
        var lastProgress = phaseStarted;
        logger.LogDebug("Checking file '{FilePath}' for raw export replay. Recognised exports are fully validated before ingestion.", filePath);
        using (var preflight = new StreamReader(stream, leaveOpen: true))
        {
            replay = await RawExportReader.ValidateAsync(preflight, cancellationToken, count => ReportProgress("Validating", count));
        }

        stream.Seek(0, SeekOrigin.Begin);
        if (!replay)
        {
            await foreach (var line in FileIngestionReader.ReadAsync(stream, cancellationToken))
            {
                yield return line;
            }

            yield break;
        }

        logger.LogDebug("Raw export validation completed for file '{FilePath}' in {ElapsedSeconds:F1}s. Starting replay through the processing pipeline.", filePath, timeProvider.GetElapsedTime(phaseStarted).TotalSeconds);
        phaseStarted = timeProvider.GetTimestamp();
        lastProgress = phaseStarted;
        var replayed = 0L;
        await foreach (var (line, lineNumber) in FileIngestionReader.ReadLinesAsync(stream, cancellationToken))
        {
            yield return RawExportReader.Decode(line, lineNumber);
            replayed++;
            ReportProgress("Replaying", replayed);
        }

        logger.LogDebug("Replayed {RecordCount} raw records from file '{FilePath}'.", replayed, filePath);

        void ReportProgress(string phase, long count)
        {
            if (timeProvider.GetElapsedTime(lastProgress) < TimeSpan.FromSeconds(10))
            {
                return;
            }

            var elapsed = timeProvider.GetElapsedTime(phaseStarted).TotalSeconds;
            logger.LogInformation("{Phase} raw export '{FilePath}': {RecordCount} records in {ElapsedSeconds:F1}s ({RecordsPerSecond:F0} records/s).", phase, filePath, count, elapsed, count / elapsed);
            lastProgress = timeProvider.GetTimestamp();
        }
    }
}
