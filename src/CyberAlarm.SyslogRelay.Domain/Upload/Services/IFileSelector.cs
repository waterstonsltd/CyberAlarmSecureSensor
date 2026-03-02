namespace CyberAlarm.SyslogRelay.Domain.Upload.Services;

public interface IFileSelector
{
    Task SelectFilesAsync(CancellationToken cancellationToken);
}
