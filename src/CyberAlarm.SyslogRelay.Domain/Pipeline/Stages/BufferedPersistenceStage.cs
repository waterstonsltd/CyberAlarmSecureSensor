using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Pipeline.Stages;

internal sealed class BufferedPersistenceStage(
    IFileManager fileManager,
    IPeriodicOperation periodicOperation,
    IOptions<PipelineOptions> options,
    ILogger<BufferedPersistenceStage> logger) : PipelineStageBase<ParsingStageOutput, bool>(options, logger), IDisposable
{
    private readonly IFileManager _fileManager = fileManager;
    private readonly IPeriodicOperation _periodicOperation = periodicOperation;
    private readonly PipelineOptions _options = options.Value;
    private readonly ILogger<BufferedPersistenceStage> _logger = logger;

    private readonly string _logsPath = fileManager.GetLogsFolder();
    private readonly List<ParsedEvent> _buffer = [];
    private readonly SemaphoreSlim _semaphoreSlim = new(1, 1);
    private readonly Lock _bufferLock = new(); // Add lock for buffer access

    private enum FlushReason
    {
        SizeReached,
        StoppingStage,
        TimeElapsed,
    }

    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        await base.StartAsync(cancellationToken);

        var bufferInterval = TimeSpan.FromSeconds(_options.PersistenceBufferIntervalInSeconds);
        _periodicOperation.Start(new(bufferInterval, PeriodicFlushBufferAsync, "buffer flush"), cancellationToken);

        _logger.LogDebug(
            "Persistence buffer configured with: Size '{BufferSize}' | Interval '{BufferInterval}' seconds",
            _options.PersistenceBufferSize,
            _options.PersistenceBufferIntervalInSeconds);
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        // Stop timer first to prevent new flushes
        await _periodicOperation.StopAsync();

        // Then flush any remaining data
        await FlushBuffer(FlushReason.StoppingStage, cancellationToken);

        await base.StopAsync(cancellationToken);
    }

    public void Dispose()
    {
        _periodicOperation?.Dispose();
        _semaphoreSlim?.Dispose();
    }

    protected override async Task<bool> ProcessMessageAsync(ParsingStageOutput input, CancellationToken cancellationToken)
    {
        bool shouldFlush;

        // Protect buffer access with lock
        lock (_bufferLock)
        {
            _buffer.Add(ToParsedEvent(input));
            shouldFlush = _buffer.Count >= _options.PersistenceBufferSize;
        }

        if (shouldFlush)
        {
            await FlushBuffer(FlushReason.SizeReached, cancellationToken);
        }

        return true;
    }

    private static ParsedEvent ToParsedEvent(ParsingStageOutput input) =>
        new(
            input.SyslogEvent.Timestamp,
            input.SyslogEvent.EventSource,
            input.SyslogEvent.RawData,
            input.PatternMatchResult?.PatternName,
            input.ParseResult);

    private async Task FlushBuffer(FlushReason reason, CancellationToken cancellationToken)
    {
        List<ParsedEvent> itemsToFlush;

        // Extract items under lock
        lock (_bufferLock)
        {
            if (_buffer.Count == 0)
            {
                return;
            }

            _logger.LogDebug("Flushing buffer: Count '{BufferCount}' | Reason '{Reason}'", _buffer.Count, reason);
            itemsToFlush = [.. _buffer];
            _buffer.Clear();
        }

        // Persist outside of lock
        await _semaphoreSlim.WaitAsync(cancellationToken);
        try
        {
            await PersistBuffer(itemsToFlush, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to persist buffer with {Count} events. Data may be lost.", itemsToFlush.Count);
        }
        finally
        {
            _semaphoreSlim.Release();
        }
    }

    private async Task PersistBuffer(List<ParsedEvent> events, CancellationToken cancellationToken)
    {
        var logFilePath = Path.Combine(_logsPath, $"{Guid.NewGuid()}.log");

        _logger.LogDebug("Persisting {Count} logs to '{LogFilePath}'.", events.Count, logFilePath);
        await _fileManager.AppendAndSaveItemsAsNdjson(events, logFilePath, cancellationToken);
    }

    private Task PeriodicFlushBufferAsync(CancellationToken cancellationToken) =>
        FlushBuffer(FlushReason.TimeElapsed, cancellationToken);
}
