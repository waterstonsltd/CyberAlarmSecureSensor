namespace CyberAlarm.SyslogRelay.Domain.Services;

public interface IApplicationManager
{
    void StopApplication(string reason = "unspecified");
}
