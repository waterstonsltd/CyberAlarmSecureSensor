namespace CyberAlarm.SyslogRelay.Domain.Upload.Services;

public interface ISecureUploader
{
    Task<UploadResult> UploadFilesAsync(CancellationToken cancellationToken);
}
