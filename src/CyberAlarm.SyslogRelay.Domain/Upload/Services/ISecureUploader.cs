namespace CyberAlarm.SyslogRelay.Domain.Upload.Services;

public interface ISecureUploader
{
    Task UploadFilesAsync(CancellationToken cancellationToken);
}
