using System.Buffers;
using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using System.Text;
using CyberAlarm.SyslogRelay.Common.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Ingestion;

public sealed class TcpListener(
    IOptions<RelayOptions> options,
    ILogger<TcpListener> logger) : IDisposable
{
    public const long MaximumBufferLength = 8 * 1024;

    private readonly RelayOptions _options = options.Value;
    private readonly ILogger<TcpListener> _logger = logger;

    private Func<SyslogEvent, CancellationToken, Task>? _ingestAction;
    private Socket? _listener;
    private CancellationTokenSource? _cts;

    public async Task StartAsync(Func<SyslogEvent, CancellationToken, Task> ingestAction, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(ingestAction);
        _ingestAction = ingestAction;

        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        _logger.LogInformation("Starting TCP listener.");
        _listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        _listener.Bind(new IPEndPoint(IPAddress.Any, _options.TcpPort));
        _listener.Listen();

        _logger.LogDebug("Waiting for up to {MaximumTcpClient} connections...", _options.MaximumTcpClients);
        try
        {
            var clientHandlers = new List<Task>(_options.MaximumTcpClients);

            while (!_cts.Token.IsCancellationRequested)
            {
                var client = await _listener.AcceptAsync(_cts.Token);

                ClearCompletedClients(clientHandlers);

                // Only handle allowed number of clients
                if (clientHandlers.Count < _options.MaximumTcpClients)
                {
                    clientHandlers.Add(HandleClient(client, _cts.Token));
                }
                else
                {
                    _logger.LogWarning("[{Client}] Disconnecting due to maximum limit reached.", GetIPEndPoint(client));
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
        }
        finally
        {
            Dispose();
            _logger.LogInformation("TCP listener stopped.");
        }
    }

    public void Stop()
    {
        _logger.LogInformation("Stopping TCP listener.");
        Dispose();
    }

    public void Dispose()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;

        _listener?.Close();
        _listener = null;
    }

    private void ClearCompletedClients(List<Task> clientHandlers)
    {
        for (var i = clientHandlers.Count - 1; i >= 0; i--)
        {
            if (clientHandlers[i].IsCompleted)
            {
                var task = clientHandlers[i];

                // Observe any exceptions
                if (task.IsFaulted && task.Exception != null)
                {
                    _logger.LogError(task.Exception, "Client handler task failed.");
                }

                clientHandlers.RemoveAt(i);
            }
        }
    }

    private async Task HandleClient(Socket clientSocket, CancellationToken cancellationToken)
    {
        var client = GetIPEndPoint(clientSocket);

        _logger.LogDebug("[{Client}] connected.", client);
        using var stream = new NetworkStream(clientSocket);
        var reader = PipeReader.Create(stream);

        try
        {
            await Read(reader, client.Address.ToString(), cancellationToken);
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

    private async Task Read(PipeReader reader, string sourceIp, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var result = await reader.ReadAsync(cancellationToken);
            var buffer = result.Buffer;
            long noNewlineLength;

            while (TryReadLine(ref buffer, out var lineBuffer, out noNewlineLength))
            {
                var line = Encoding.UTF8.GetString(lineBuffer);
                await (_ingestAction?.Invoke(SyslogEvent.FromTcp(sourceIp, line), cancellationToken) ?? Task.CompletedTask);
            }

            // Tell the PipeReader how much of the buffer has been consumed and examined.
            reader.AdvanceTo(buffer.Start, buffer.End);

            // Check if the buffer without a newline exceeds the maximum length.
            if (noNewlineLength > MaximumBufferLength)
            {
                _logger.LogWarning("[{Client}] disconnecting as buffer length '{NoNewlineLength}' exceeds maximum limit.", sourceIp, noNewlineLength);
                break;
            }

            // Stop reading if there's no more data coming.
            if (result.IsCompleted)
            {
                break;
            }
        }
    }

    private static bool TryReadLine(ref ReadOnlySequence<byte> buffer, out ReadOnlySequence<byte> line, out long noNewlineLength)
    {
        // Look for a EOL in the buffer.
        var position = buffer.PositionOf((byte)'\n');
        if (position is null)
        {
            noNewlineLength = buffer.Length;
            line = default;
            return false;
        }

        noNewlineLength = Math.Min(position.Value.GetInteger(), buffer.Length);
        if (noNewlineLength > MaximumBufferLength)
        {
            line = default;
            return false;
        }

        // Skip the line + the \n.
        line = buffer.Slice(0, position.Value);
        buffer = buffer.Slice(buffer.GetPosition(1, position.Value));
        return true;
    }

    private static IPEndPoint GetIPEndPoint(Socket socket) =>
        socket.RemoteEndPoint switch
        {
            IPEndPoint ipEndPoint => ipEndPoint,
            _ => new(IPAddress.Any, 0),
        };
}
