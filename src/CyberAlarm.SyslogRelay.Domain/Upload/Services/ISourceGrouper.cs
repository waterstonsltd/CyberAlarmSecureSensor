namespace CyberAlarm.SyslogRelay.Domain.Upload.Services;

public interface ISourceGrouper
{
    Task GroupLogsBySourceAsync(CancellationToken cancellationToken);
}
