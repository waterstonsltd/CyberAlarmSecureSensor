using System.Threading.Channels;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Services;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Pipeline.Stages;

internal sealed class BufferedPersistenceStage(
    IFileManager fileManager,
    IPeriodicOperation periodicOperation,
    PipelineStageServices services,
    ILogger<BufferedPersistenceStage> logger)
    : PipelineStageBase<ValidationStageOutput, bool>(services, logger), IDisposable
{
    private readonly IFileManager _fileManager = fileManager;
    private readonly IPeriodicOperation _periodicOperation = periodicOperation;
    private readonly PipelineOptions _options = services.Options;
    private readonly PipelineMetrics _metrics = services.Metrics;
    private readonly ILogger<BufferedPersistenceStage> _logger = logger;

    private readonly string _logsPath = fileManager.GetLogsFolder();

    // In-memory accumulation buffer. Accessed from both the processing loop worker and the
    // periodic timer thread, so all reads/writes must be guarded by _bufferLock.
    private readonly List<ParsedEvent> _buffer = [];
    private readonly object _bufferLock = new();

    // Completed batches are handed to the writer via this channel so the processing loop
    // never blocks on disk I/O. Capacity of 8 means up to ~8,000 events can be queued
    // for writing before the processing loop applies backpressure.
    private readonly Channel<(List<ParsedEvent> Events, FlushReason Reason)> _flushQueue =
        Channel.CreateBounded<(List<ParsedEvent>, FlushReason)>(
            new BoundedChannelOptions(8)
            {
                FullMode = BoundedChannelFullMode.Wait,
                SingleReader = true,
                SingleWriter = false,
            });

    private Task _writerTask = Task.CompletedTask;

    private enum FlushReason
    {
        SizeReached,
        StoppingStage,
        TimeElapsed,
    }

    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        _writerTask = RunWriterAsync(cancellationToken);

        await base.StartAsync(cancellationToken);

        var bufferInterval = TimeSpan.FromSeconds(_options.PersistenceBufferIntervalInSeconds);
        _periodicOperation.Start(new(bufferInterval, PeriodicFlushBufferAsync, "buffer flush", true), cancellationToken);

        _logger.LogDebug(
            "Persistence buffer configured with: Size '{BufferSize}' | Interval '{BufferInterval}' seconds",
            _options.PersistenceBufferSize,
            _options.PersistenceBufferIntervalInSeconds);
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await _periodicOperation.StopAsync();

        // Flush remaining in-memory items then signal the writer there is no more work.
        await EnqueueFlush(FlushReason.StoppingStage, cancellationToken);
        _flushQueue.Writer.Complete();
        await _writerTask;

        await base.StopAsync(cancellationToken);
    }

    public void Dispose() => _periodicOperation?.Dispose();

    protected override async Task<bool> ProcessMessageAsync(ValidationStageOutput input, CancellationToken cancellationToken)
    {
        bool shouldFlush;

        lock (_bufferLock)
        {
            _buffer.Add(ToParsedEvent(input, _options.UploadRawLogs));
            shouldFlush = _buffer.Count >= _options.PersistenceBufferSize;
        }

        if (shouldFlush)
        {
            await EnqueueFlush(FlushReason.SizeReached, cancellationToken);
        }

        return true;
    }

    private async Task EnqueueFlush(FlushReason reason, CancellationToken cancellationToken)
    {
        List<ParsedEvent>? batch = null;

        lock (_bufferLock)
        {
            if (_buffer.Count == 0)
            {
                return;
            }

            // Swap out the buffer under the lock so the processing loop can immediately
            // continue while the writer task persists the previous batch independently.
            batch = new List<ParsedEvent>(_buffer);
            _buffer.Clear();
        }

        _logger.LogDebug("Queuing flush: Count '{BatchCount}' | Reason '{Reason}'", batch.Count, reason);
        await _flushQueue.Writer.WriteAsync((batch, reason), cancellationToken);
    }

    private async Task RunWriterAsync(CancellationToken cancellationToken)
    {
        await foreach (var (events, reason) in _flushQueue.Reader.ReadAllAsync(cancellationToken))
        {
            _metrics.BufferFlushes.Add(1, new KeyValuePair<string, object?>("reason", reason.ToString()));
            _metrics.BufferFlushSize.Record(events.Count);

            try
            {
                await PersistBuffer(events, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to persist buffer with {Count} events. Data may be lost.", events.Count);
            }
        }
    }

    private static ParsedEvent ToParsedEvent(ValidationStageOutput input, bool includeRawData) =>
        new(
            input.SyslogEvent.Timestamp,
            input.SyslogEvent.EventSource,
            includeRawData ? input.SyslogEvent.RawData : null,
            input.PatternMatchResult?.PatternName,
            input.ParseResult,
            input.ValidationResult.ValidationStatus);

    private async Task PersistBuffer(List<ParsedEvent> events, CancellationToken cancellationToken)
    {
        var logFilePath = Path.Combine(_logsPath, $"{Guid.NewGuid()}.log");

        _logger.LogDebug("Persisting {Count} logs to '{LogFilePath}'.", events.Count, logFilePath);
        await _fileManager.AppendAndSaveItemsAsNdjson(events, logFilePath, cancellationToken);
    }

    private Task PeriodicFlushBufferAsync(CancellationToken cancellationToken) =>
        EnqueueFlush(FlushReason.TimeElapsed, cancellationToken);
}
