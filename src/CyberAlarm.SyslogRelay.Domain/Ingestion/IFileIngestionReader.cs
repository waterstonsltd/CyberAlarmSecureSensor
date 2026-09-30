namespace CyberAlarm.SyslogRelay.Domain.Ingestion;

public interface IFileIngestionReader
{
    IAsyncEnumerable<string> ReadAsync(string filePath, CancellationToken cancellationToken);
}
