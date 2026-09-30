using System.Buffers;
using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using System.Text;
using CyberAlarm.SyslogRelay.Common.Models;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Ingestion;

internal static class SocketListenerUtilities
{
    public const long MaximumBufferLength = 8 * 1024;

    public static void ClearCompletedClients(List<Task> clientHandlers, ILogger logger, string failureMessage)
    {
        for (var i = clientHandlers.Count - 1; i >= 0; i--)
        {
            if (clientHandlers[i].IsCompleted)
            {
                var task = clientHandlers[i];

                if (task.IsFaulted && task.Exception != null)
                {
                    logger.LogError(task.Exception, failureMessage);
                }

                clientHandlers.RemoveAt(i);
            }
        }
    }

    public static async Task ReadAsync(
        PipeReader reader,
        string sourceIp,
        Func<string, string, SyslogEvent> eventFactory,
        Func<SyslogEvent, CancellationToken, Task>? ingestAction,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var result = await reader.ReadAsync(cancellationToken);
            var buffer = result.Buffer;
            long noNewlineLength;

            while (TryReadLine(ref buffer, out var lineBuffer, out noNewlineLength))
            {
                var line = Encoding.UTF8.GetString(lineBuffer);
                await (ingestAction?.Invoke(eventFactory(sourceIp, line), cancellationToken) ?? Task.CompletedTask);
            }

            reader.AdvanceTo(buffer.Start, buffer.End);

            if (noNewlineLength > MaximumBufferLength)
            {
                logger.LogWarning("[{Client}] disconnecting as buffer length '{NoNewlineLength}' exceeds maximum limit.", sourceIp, noNewlineLength);
                break;
            }

            if (result.IsCompleted)
            {
                break;
            }
        }
    }

    public static IPEndPoint GetIPEndPoint(Socket socket) =>
        socket.RemoteEndPoint switch
        {
            IPEndPoint ipEndPoint => ipEndPoint,
            _ => new(IPAddress.Any, 0),
        };

    private static bool TryReadLine(ref ReadOnlySequence<byte> buffer, out ReadOnlySequence<byte> line, out long noNewlineLength)
    {
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

        line = buffer.Slice(0, position.Value);
        buffer = buffer.Slice(buffer.GetPosition(1, position.Value));
        return true;
    }
}
