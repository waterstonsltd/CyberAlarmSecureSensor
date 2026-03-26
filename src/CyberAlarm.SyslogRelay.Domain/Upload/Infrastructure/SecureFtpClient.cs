using CyberAlarm.SyslogRelay.Domain.Upload.Extensions;
using Renci.SshNet;

namespace CyberAlarm.SyslogRelay.Domain.Upload.Infrastructure;

public sealed class SecureFtpClient : ISecureFtpClient
{
    private readonly SftpClient _secureFtpClient;

    public SecureFtpClient(string hostName, string userName, PrivateKeyFile privateKeyFile, string hostFingerprint)
    {
        _secureFtpClient = new(new ConnectionInfo(hostName, userName, new PrivateKeyAuthenticationMethod(userName, privateKeyFile)));
        _secureFtpClient.HostKeyReceived += (sender, e) =>
        {
            e.CanTrust = e.FingerPrintSHA256.MatchesHostFingerprint(hostFingerprint);
        };
    }

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
