using System.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Velopack;

namespace CyberAlarm.SyslogRelay.ConsoleApp;

internal static class WindowsHost
{
    internal const string ServiceName = "CyberAlarm Syslog Relay";
    internal const string ConfigFileName = "appsettings.windows.local.json";

    private static readonly string DataRootPath =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "syslog-relay");

    internal static string ConfigurationPath =>
        Path.Combine(DataRootPath, ConfigFileName);

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    internal static void AddWindowsPlatformSupport(this IHostApplicationBuilder builder)
    {
        builder.Configuration.AddJsonFile("appsettings.windows.json", optional: true, reloadOnChange: true);
        builder.Configuration.AddJsonFile(ConfigurationPath, optional: true, reloadOnChange: true);
        builder.Services.AddWindowsService(options => options.ServiceName = ServiceName);
        builder.Services.AddHostedService<WindowsUpdateService>();
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    internal static void RunVelopackHooks()
    {
        VelopackApp.Build()
            .SetAutoApplyOnStartup(false)
            .OnAfterInstallFastCallback(_ => Install())
            .OnBeforeUpdateFastCallback(_ => StopService())
            .OnAfterUpdateFastCallback(_ => StartService())
            .OnBeforeUninstallFastCallback(_ => Uninstall())
            .Run();
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    internal static void EnsureDataDirectories()
    {
        Directory.CreateDirectory(DataRootPath);
        Directory.CreateDirectory(Path.Combine(DataRootPath, "logs"));
        Directory.CreateDirectory(Path.Combine(DataRootPath, "drop"));
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void Install()
    {
        EnsureDataDirectories();

        // Use AppContext.BaseDirectory rather than Environment.ProcessPath because
        // the MSI runs hooks via a staging path; BaseDirectory is the final install location.
        var exePath = Path.Combine(AppContext.BaseDirectory, "CyberAlarm.SyslogRelay.ConsoleApp.exe");
        if (!File.Exists(exePath))
        {
            return;
        }

        if (!ServiceExists())
        {
            RunScCommand($"create \"{ServiceName}\" start= auto binPath= \"{exePath}\"");
        }

        StartService();
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void Uninstall()
    {
        StopService();
        RunScCommand($"delete \"{ServiceName}\"", ignoreExitCode: true);
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void StartService() =>
        RunScCommand($"start \"{ServiceName}\"", ignoreExitCode: true);

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void StopService() =>
        RunScCommand($"stop \"{ServiceName}\"", ignoreExitCode: true);

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static bool ServiceExists()
    {
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = "sc.exe",
            Arguments = $"query \"{ServiceName}\"",
            CreateNoWindow = true,
            UseShellExecute = false,
        });

        process?.WaitForExit();
        return process is { ExitCode: 0 };
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void RunScCommand(string arguments, bool ignoreExitCode = false)
    {
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = "sc.exe",
            Arguments = arguments,
            CreateNoWindow = true,
            UseShellExecute = false,
        });

        process?.WaitForExit();
        if (!ignoreExitCode && process is { ExitCode: not 0 })
        {
            throw new InvalidOperationException($"sc.exe {arguments} failed with exit code {process.ExitCode}.");
        }
    }
}
