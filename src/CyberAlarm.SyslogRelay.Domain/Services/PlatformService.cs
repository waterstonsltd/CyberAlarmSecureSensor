using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace CyberAlarm.SyslogRelay.Domain.Services;

internal sealed class PlatformService : IPlatformService
{
    public Platform GetPlatform()
    {
        var isDocker = File.Exists("/.dockerenv");

        return new(
            Os: GetOperatingSystemDescription(),
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

    private static string GetOperatingSystemDescription()
    {
        if (!OperatingSystem.IsWindows())
        {
            return RuntimeInformation.OSDescription;
        }

        const string currentVersionKeyPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(currentVersionKeyPath);
            if (key is null)
            {
                return RuntimeInformation.OSDescription;
            }

            var productName = key.GetValue("ProductName") as string;
            var displayVersion = key.GetValue("DisplayVersion") as string;
            var releaseId = key.GetValue("ReleaseId") as string;
            var installationType = key.GetValue("InstallationType") as string;

            if (string.IsNullOrWhiteSpace(productName))
            {
                return RuntimeInformation.OSDescription;
            }

            var segments = new List<string> { productName.Trim() };

            if (!string.IsNullOrWhiteSpace(displayVersion))
            {
                segments.Add(displayVersion.Trim());
            }
            else if (!string.IsNullOrWhiteSpace(releaseId) && !string.Equals(releaseId, "2009", StringComparison.OrdinalIgnoreCase))
            {
                segments.Add(releaseId.Trim());
            }

            if (productName.Contains("Server", StringComparison.OrdinalIgnoreCase) &&
                !string.IsNullOrWhiteSpace(installationType) &&
                !string.Equals(installationType, "Server", StringComparison.OrdinalIgnoreCase))
            {
                segments.Add($"({installationType.Trim()})");
            }

            return string.Join(' ', segments);
        }
        catch
        {
            return RuntimeInformation.OSDescription;
        }
    }
}
