using System.Net;
using System.Net.Sockets;
using CyberAlarm.SyslogRelay.Common.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Ingestion;

public sealed class UdpListener(
    IOptions<RelayOptions> options,
    ILogger<UdpListener> logger) : IDisposable
{
    private readonly RelayOptions _options = options.Value;
    private readonly ILogger<UdpListener> _logger = logger;

    private UdpClient? _udpClient;
    private CancellationTokenSource? _cts;

    public async Task StartAsync(Func<SyslogEvent, CancellationToken, Task> ingestAction, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(ingestAction);

        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        _logger.LogInformation("Starting UDP listener.");
        _udpClient = new(new IPEndPoint(IPAddress.Any, _options.UdpPort));

        try
        {
            while (!_cts.Token.IsCancellationRequested)
            {
                var result = await _udpClient.ReceiveAsync(_cts.Token);
                await ingestAction.Invoke(SyslogEvent.FromUdp(result.RemoteEndPoint, result.Buffer), _cts.Token);
            }
        }
        catch (OperationCanceledException)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                _logger.LogInformation("UDP listener was cancelled.");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error running UDP listener.");
        }
        finally
        {
            Dispose();
            _logger.LogInformation("UDP listener stopped.");
        }
    }

    public void Stop()
    {
        _logger.LogInformation("Stopping UDP listener.");
        Dispose();
    }

    public void Dispose()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;

        _udpClient?.Close();
        _udpClient = null;
    }
}
