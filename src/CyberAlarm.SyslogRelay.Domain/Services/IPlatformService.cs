namespace CyberAlarm.SyslogRelay.Domain.Services;

public interface IPlatformService
{
    Platform GetPlatform();

    PlatformType GetPlatformType();
}
