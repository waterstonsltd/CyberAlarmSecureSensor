using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Threading.Channels;
using CyberAlarm.SyslogRelay.Domain.HealthCheck;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Pipeline.Stages;

internal abstract class PipelineStageBase<TInput, TOutput> : IPipelineStage<TInput>, IPipelineStageLink<TOutput>
{
    private readonly PipelineStageServices _services;
    private readonly IHealthToken _healthToken;
    private readonly ILogger _logger;
    private readonly string _stageName;
    private readonly Channel<TInput> _inputChannel;
    private readonly Lock _lock = new();
    private readonly PipelineMetrics _metrics;
    private readonly TagList _stageTags;

    private CancellationTokenSource? _processingCts;
    private Task? _processingTask;
    private bool _isStarted;

    protected PipelineStageBase(PipelineStageServices services, ILogger logger)
    {
        _stageName = GetType().Name;

        _services = services;
        _healthToken = services.HealthCheckService.GetHealthToken(_stageName);
        _logger = logger;
        _metrics = services.Metrics;
        _stageTags = new TagList { { "stage", _stageName } };

        _inputChannel = Channel.CreateBounded<TInput>(
            new BoundedChannelOptions(services.Options.ChannelCapacity)
            {
                FullMode = BoundedChannelFullMode.Wait,
                SingleReader = false,
                SingleWriter = false,
            });

        _metrics.RegisterChannelDepth(_stageName, () => _inputChannel.Reader.Count);
    }

    public IPipelineStage<TOutput>? NextStage { get; set; }

    IPipelineStage? IPipelineStage.NextStage => NextStage;

    protected virtual int DegreeOfParallelism => 1;

    public async Task EnqueueAsync(TInput input, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);

        try
        {
            await _inputChannel.Writer.WriteAsync(input, cancellationToken);
        }
        catch (ChannelClosedException ex)
        {
            _logger.LogWarning(ex, "Attempted to enqueue to closed channel in {StageName}.", _stageName);
            throw new InvalidOperationException($"Cannot enqueue to stopped stage {_stageName}.");
        }
    }

    public virtual async Task StartAsync(CancellationToken cancellationToken)
    {
        lock (_lock)
        {
            if (_isStarted)
            {
                _logger.LogWarning("Stage {StageName} already started.", _stageName);
                return;
            }

            _logger.LogDebug("Starting stage {StageName}.", _stageName);

            _processingCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

            var token = _processingCts.Token;
            var degree = DegreeOfParallelism;

            if (degree > 1)
            {
                var tasks = new Task[degree];
                for (var i = 0; i < degree; i++)
                {
                    tasks[i] = ProcessingLoopAsync(token);
                }

                _processingTask = Task.WhenAll(tasks);
            }
            else
            {
                _processingTask = ProcessingLoopAsync(token);
            }

            _isStarted = true;

            _logger.LogInformation("Stage {StageName} started.", _stageName);
        }

        await _healthToken.HealthyAsync(cancellationToken);
    }

    public virtual async Task StopAsync(CancellationToken cancellationToken)
    {
        lock (_lock)
        {
            if (!_isStarted)
            {
                _logger.LogWarning("Stage {StageName} not started.", _stageName);
                return;
            }
        }

        try
        {
            _logger.LogDebug("Stopping stage {StageName}.", _stageName);
            _inputChannel.Writer.Complete();

            if (_processingCts != null)
            {
                await _processingCts.CancelAsync();
            }

            if (_processingTask != null)
            {
                await _processingTask;
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("Stage {StageName} processing cancelled.", _stageName);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error when stopping stage {StageName}.", _stageName);
        }
        finally
        {
            _processingCts?.Dispose();
            _isStarted = false;

            _logger.LogInformation("Stage {StageName} stopped.", _stageName);
        }
    }

    protected abstract Task<TOutput> ProcessMessageAsync(TInput input, CancellationToken cancellationToken);

    private async Task ProcessingLoopAsync(CancellationToken cancellationToken)
    {
        _logger.LogDebug("Starting stage {StageName} processing loop.", _stageName);

        try
        {
            await foreach (var input in _inputChannel.Reader.ReadAllAsync(cancellationToken))
            {
                await ProcessItemAsync(input, cancellationToken);
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("Stage {StageName} processing loop cancelled.", _stageName);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Error occurred in stage {StageName} processing loop.", _stageName);

            await _healthToken.UnhealthyAsync(cancellationToken);
            _services.ApplicationManager.StopApplication();
        }

        _logger.LogDebug("Stage {StageName} processing loop completed.", _stageName);
    }

    private async Task ProcessItemAsync(TInput input, CancellationToken cancellationToken)
    {
        var startTimestamp = Stopwatch.GetTimestamp();
        try
        {
            var output = await ProcessMessageAsync(input, cancellationToken);

            if (NextStage != null)
            {
                await NextStage.EnqueueAsync(output, cancellationToken);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing item in stage {StageName}.", _stageName);
        }
        finally
        {
            _metrics.ProcessingDuration.Record(
                Stopwatch.GetElapsedTime(startTimestamp).TotalMilliseconds,
                _stageTags);
            _metrics.ItemsProcessed.Add(1, _stageTags);
        }
    }
}
