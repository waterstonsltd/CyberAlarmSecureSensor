using CyberAlarm.SyslogRelay.Domain.Services;
using Microsoft.Extensions.Hosting;

namespace CyberAlarm.SyslogRelay.ConsoleApp;

internal sealed class ApplicationManager(IHostApplicationLifetime hostApplication) : IApplicationManager
{
    private readonly IHostApplicationLifetime _hostApplication = hostApplication;

    public void StopApplication() => _hostApplication.StopApplication();
}
