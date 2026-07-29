using System.Text;
using Renci.SshNet;

namespace CyberAlarm.SyslogRelay.Domain.Upload.Infrastructure;

public class SecureFtpClientFactory : ISecureFtpClientFactory
{
    public ISecureFtpClient Create(string hostName, string userName, string privateKey, IReadOnlyList<string> hostFingerprints)
    {
        var privateKeyFile = new PrivateKeyFile(new MemoryStream(Encoding.UTF8.GetBytes(privateKey)));
        return new SecureFtpClient(hostName, userName, privateKeyFile, hostFingerprints);
    }
}
