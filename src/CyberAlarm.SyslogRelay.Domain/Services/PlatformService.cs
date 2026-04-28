using System.Runtime.InteropServices;

namespace CyberAlarm.SyslogRelay.Domain.Services;

internal sealed class PlatformService : IPlatformService
{
    public Platform GetPlatform()
    {
        var isDocker = File.Exists("/.dockerenv");

        return new(
            Os: RuntimeInformation.OSDescription,
            Runtime: RuntimeInformation.FrameworkDescription,
            Architecture: RuntimeInformation.OSArchitecture.ToString(),
            isDocker);
    }

    public PlatformType GetPlatformType()
    {
        if (OperatingSystem.IsLinux())
        {
            return PlatformType.Linux;
        }

        if (OperatingSystem.IsWindows())
        {
            return PlatformType.Windows;
        }

        return PlatformType.NotSupported;
    }
}
