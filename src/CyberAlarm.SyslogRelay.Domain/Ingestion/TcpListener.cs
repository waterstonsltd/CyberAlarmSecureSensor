using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.HealthCheck;
using CyberAlarm.SyslogRelay.Domain.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Ingestion;

public sealed class TcpListener(
    IApplicationManager applicationManager,
    IHealthCheckService healthCheckService,
    IOptions<RelayOptions> options,
    ILogger<TcpListener> logger) : IDisposable
{
    private readonly IApplicationManager _applicationManager = applicationManager;
    private readonly IHealthToken _healthToken = healthCheckService.GetHealthToken(nameof(TcpListener));
    private readonly RelayOptions _options = options.Value;
    private readonly ILogger<TcpListener> _logger = logger;

    private Func<SyslogEvent, CancellationToken, Task>? _ingestAction;
    private Socket? _listener;
    private CancellationTokenSource? _cts;

    public async Task StartAsync(Func<SyslogEvent, CancellationToken, Task> ingestAction, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(ingestAction);
        _ingestAction = ingestAction;

        if (_options.TlsEnabled && !_options.AllowPlaintextListenersWhenTlsEnabled)
        {
            await _healthToken.UnregisterAsync(cancellationToken);
            _logger.LogInformation(
                "TCP listener is disabled because TLS is enabled. Set AllowPlaintextListenersWhenTlsEnabled=true to keep plaintext listeners enabled.");
            return;
        }

        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        _logger.LogInformation("Starting TCP listener.");
        _listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        _listener.Bind(new IPEndPoint(IPAddress.Any, _options.TcpPort));
        _listener.Listen();

        _logger.LogDebug("Waiting for up to {MaximumTcpClient} connections...", _options.MaximumTcpClients);
        await _healthToken.HealthyAsync(_cts.Token);

        try
        {
            var clientHandlers = new List<Task>(_options.MaximumTcpClients);

            while (!_cts.Token.IsCancellationRequested)
            {
                var client = await _listener.AcceptAsync(_cts.Token);

                SocketListenerUtilities.ClearCompletedClients(clientHandlers, _logger, "Client handler task failed.");

                // Only handle allowed number of clients
                if (clientHandlers.Count < _options.MaximumTcpClients)
                {
                    clientHandlers.Add(HandleClient(client, _cts.Token));
                }
                else
                {
                    _logger.LogWarning("[{Client}] Disconnecting due to maximum limit reached.", SocketListenerUtilities.GetIPEndPoint(client));
                    client.Shutdown(SocketShutdown.Both);
                    client.Close();
                }
            }
        }
        catch (OperationCanceledException)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                _logger.LogInformation("TCP listener was cancelled.");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error running TCP listener.");

            await _healthToken.UnhealthyAsync(_cts.Token);
            _applicationManager.StopApplication();
        }
        finally
        {
            Dispose();
            _logger.LogInformation("TCP listener stopped.");
        }
    }

    public void Dispose()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;

        _listener?.Close();
        _listener = null;
    }

    private async Task HandleClient(Socket clientSocket, CancellationToken cancellationToken)
    {
        var client = SocketListenerUtilities.GetIPEndPoint(clientSocket);

        _logger.LogDebug("[{Client}] connected.", client);
        using var stream = new NetworkStream(clientSocket);
        var reader = PipeReader.Create(stream);

        try
        {
            await SocketListenerUtilities.ReadAsync(reader, client.Address.ToString(), SyslogEvent.FromTcp, _ingestAction, _logger, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            _logger.LogDebug("[{Client}] handling cancelled.", client);
        }
        catch (IOException ex)
            when (ex.InnerException is SocketException { SocketErrorCode: SocketError.ConnectionReset })
        {
            _logger.LogWarning("[{Client}] {ErrorMessage}", client, ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred when ingesting tcp log data from [{Client}].", client);
        }
        finally
        {
            await reader.CompleteAsync();

            clientSocket.Shutdown(SocketShutdown.Both);
            clientSocket.Close();

            _logger.LogDebug("[{Client}] disconnected.", client);
        }
    }
}
