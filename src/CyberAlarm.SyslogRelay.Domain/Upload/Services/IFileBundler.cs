namespace CyberAlarm.SyslogRelay.Domain.Upload.Services;

public interface IFileBundler
{
    Task BundleFilesAsync(CancellationToken cancellationToken);
}
