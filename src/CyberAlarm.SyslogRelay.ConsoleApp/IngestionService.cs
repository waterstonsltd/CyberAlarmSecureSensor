using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Ingestion;
using CyberAlarm.SyslogRelay.Domain.Pipeline;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.ConsoleApp;

internal sealed class IngestionService(
    ISyslogRelayPipeline<SyslogEvent> pipeline,
    FileWatcher fileWatcher,
    TcpListener tcpListener,
    UdpListener udpListener,
    ILogger<IngestionService> logger) : IHostedService
{
    private readonly ISyslogRelayPipeline<SyslogEvent> _pipeline = pipeline;
    private readonly FileWatcher _fileWatcher = fileWatcher;
    private readonly TcpListener _tcpListener = tcpListener;
    private readonly UdpListener _udpListener = udpListener;
    private readonly ILogger<IngestionService> _logger = logger;

    private readonly List<Task> _tasks = [];

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Starting ingestion services.");

        _tasks.Add(_pipeline.StartAsync(cancellationToken));
        _tasks.Add(_fileWatcher.StartAsync(_pipeline.EnqueueAsync, cancellationToken));
        _tasks.Add(_tcpListener.StartAsync(_pipeline.EnqueueAsync, cancellationToken));
        _tasks.Add(_udpListener.StartAsync(_pipeline.EnqueueAsync, cancellationToken));
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Stopping ingestion services.");

        if (_tasks.Count == 0)
        {
            return;
        }

        try
        {
            _udpListener.Stop();
            _tcpListener.Stop();
            await _fileWatcher.StopAsync();
            await _pipeline.StopAsync(cancellationToken);
        }
        finally
        {
            foreach (var task in _tasks)
            {
                await task.WaitAsync(cancellationToken).ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
            }

            _tasks.Clear();
        }
    }
}
