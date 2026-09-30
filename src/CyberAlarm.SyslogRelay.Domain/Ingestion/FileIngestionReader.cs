using System.Runtime.CompilerServices;
using CyberAlarm.SyslogRelay.Domain.Services;

namespace CyberAlarm.SyslogRelay.Domain.Ingestion;

public sealed class FileIngestionReader(IFileManager fileManager) : IFileIngestionReader
{
    public async IAsyncEnumerable<string> ReadAsync(string filePath, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var stream = fileManager.OpenStreamFromFile(filePath, cancellationToken);
        await foreach (var line in ReadAsync(stream, cancellationToken))
        {
            yield return line;
        }
    }

    internal static async IAsyncEnumerable<string> ReadAsync(Stream stream, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await foreach (var (line, _) in ReadLinesAsync(stream, cancellationToken))
        {
            yield return line;
        }
    }

    // The caller owns the stream so detection and replay can share the same open file.
    internal static async IAsyncEnumerable<(string Text, long LineNumber)> ReadLinesAsync(
        Stream stream, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        using var reader = new StreamReader(stream, leaveOpen: true);
        var lineNumber = 0L;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var line = await reader.ReadLineAsync(cancellationToken);
            if (line is null)
            {
                yield break;
            }

            lineNumber++;
            if (!string.IsNullOrWhiteSpace(line))
            {
                yield return (line, lineNumber);
            }
        }
    }
}
