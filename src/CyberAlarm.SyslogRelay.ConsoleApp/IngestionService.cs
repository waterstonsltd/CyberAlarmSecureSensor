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
    ILogger<IngestionService> logger) : BackgroundService
{
    private readonly ISyslogRelayPipeline<SyslogEvent> _pipeline = pipeline;
    private readonly FileWatcher _fileWatcher = fileWatcher;
    private readonly TcpListener _tcpListener = tcpListener;
    private readonly UdpListener _udpListener = udpListener;
    private readonly ILogger<IngestionService> _logger = logger;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Starting ingestion services.");

        try
        {
            var task = await Task.WhenAny(
                _pipeline.StartAsync(stoppingToken),
                _fileWatcher.StartAsync(_pipeline.EnqueueAsync, stoppingToken),
                _tcpListener.StartAsync(_pipeline.EnqueueAsync, stoppingToken),
                _udpListener.StartAsync(_pipeline.EnqueueAsync, stoppingToken));

            await task;
        }
        finally
        {
            _logger.LogInformation("Exiting ingestion services.");
        }
    }
}
