namespace CyberAlarm.SyslogRelay.Domain.Upload.Infrastructure;

public interface ISecureFtpClient : IDisposable
{
    bool IsConnected { get; }

    void Connect();

    void Disconnect();

    Task UploadFileAsync(Stream input, string path, CancellationToken cancellationToken);

    bool Exists(string folder);

    Task CreateDirectoryAsync(string folder);
}
