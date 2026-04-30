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
    TlsListener tlsListener,
    UdpListener udpListener,
    ILogger<IngestionService> logger) : BackgroundService
{
    private readonly ISyslogRelayPipeline<SyslogEvent> _pipeline = pipeline;
    private readonly FileWatcher _fileWatcher = fileWatcher;
    private readonly TcpListener _tcpListener = tcpListener;
    private readonly TlsListener _tlsListener = tlsListener;
    private readonly UdpListener _udpListener = udpListener;
    private readonly ILogger<IngestionService> _logger = logger;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Starting ingestion services.");

        try
        {
            var tasks = new Dictionary<Task, string>
            {
                [_pipeline.StartAsync(stoppingToken)] = "pipeline",
                [_fileWatcher.StartAsync(_pipeline.EnqueueAsync, stoppingToken)] = "file watcher",
                [_tcpListener.StartAsync(_pipeline.EnqueueAsync, stoppingToken)] = "TCP listener",
                [_tlsListener.StartAsync(_pipeline.EnqueueAsync, stoppingToken)] = "TLS listener",
                [_udpListener.StartAsync(_pipeline.EnqueueAsync, stoppingToken)] = "UDP listener",
            };

            await foreach (var task in Task.WhenEach(tasks.Keys))
            {
                try
                {
                    await task;
                }
                catch (Exception ex) when (ex is not OperationCanceledException || !stoppingToken.IsCancellationRequested)
                {
                    throw new InvalidOperationException($"Ingestion component {tasks[task]} terminated unexpectedly.", ex);
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            _logger.LogInformation("Ingestion service was cancelled.");
        }

        _logger.LogInformation("Exiting ingestion services.");
    }
}
