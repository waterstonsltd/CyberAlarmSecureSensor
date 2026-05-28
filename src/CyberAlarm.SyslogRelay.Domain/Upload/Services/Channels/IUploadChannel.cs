namespace CyberAlarm.SyslogRelay.Domain.Upload.Services.Channels;

internal enum UploadFileOutcome
{
    Uploaded,
    Failed,
    FailedStop,
    Blocked,
    TryNextChannel,
}

internal interface IUploadChannel : IAsyncDisposable
{
    Task<UploadFileOutcome> UploadFileAsync(string localFile, string targetPath, CancellationToken cancellationToken);
}
