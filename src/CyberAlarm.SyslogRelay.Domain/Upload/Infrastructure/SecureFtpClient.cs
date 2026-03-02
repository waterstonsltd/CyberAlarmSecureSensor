using Renci.SshNet;

namespace CyberAlarm.SyslogRelay.Domain.Upload.Infrastructure;

public sealed class SecureFtpClient(string hostName, string userName, PrivateKeyFile privateKeyFile) : ISecureFtpClient
{
    private readonly SftpClient _secureFtpClient
        = new(new ConnectionInfo(hostName, userName, new PrivateKeyAuthenticationMethod(userName, privateKeyFile)));

    public bool IsConnected => _secureFtpClient.IsConnected;

    public void Connect() => _secureFtpClient.Connect();

    public async Task CreateDirectoryAsync(string folder) =>
        await _secureFtpClient.CreateDirectoryAsync(folder);

    public void Disconnect() => _secureFtpClient.Disconnect();

    public void Dispose() => _secureFtpClient.Dispose();

    public bool Exists(string folder) => _secureFtpClient.Exists(folder);

    public async Task UploadFileAsync(Stream input, string path, CancellationToken cancellationToken)
    {
        await _secureFtpClient.UploadFileAsync(input, path, cancellationToken);
    }
}
