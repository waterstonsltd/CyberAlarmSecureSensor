namespace CyberAlarm.SyslogRelay.Domain.Upload.Infrastructure;

public interface ISecureFtpClientFactory
{
    ISecureFtpClient Create(string hostName, string userName, string privateKey);
}
