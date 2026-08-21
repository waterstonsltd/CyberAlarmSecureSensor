using CyberAlarm.SyslogRelay.Domain.Services;
using Microsoft.Extensions.Hosting;

namespace CyberAlarm.SyslogRelay.ConsoleApp;

internal sealed class ApplicationManager(IHostApplicationLifetime hostApplication) : IApplicationManager
{
    private readonly IHostApplicationLifetime _hostApplication = hostApplication;

    public string ShutdownReason { get; private set; } = "external signal (OS/SCM)";

    public void StopApplication(string reason = "unspecified")
    {
        ShutdownReason = reason;
        _hostApplication.StopApplication();
    }
}
