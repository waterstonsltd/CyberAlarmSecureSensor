using CyberAlarm.SyslogRelay.Domain;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Initialisation;
using CyberAlarm.SyslogRelay.Domain.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.ConsoleApp;

internal static class Program
{
    public static async Task Main(string[] args)
    {
        var builder = Host.CreateApplicationBuilder(args);
        builder.Services
            .AddDomainServices(builder.Configuration)
            .AddEventBundlerServices()
            .AddScheduledServices(builder.Configuration)
            .AddHostedService<UploadService>()
            .AddHostedService<IngestionService>();

        builder.Services.AddSingleton<IApplicationManager, ApplicationManager>();

        var host = builder.Build();
        var logger = host.Services.GetRequiredService<ILogger<IHost>>();

        using var scope = host.Services.CreateScope();
        var initialisationService = scope.ServiceProvider.GetRequiredService<InitialisationService>();

        // Initialise relay and run checks
        var result = await initialisationService.InitialiseAsync(CancellationToken.None);
        if (result.IsFailed)
        {
            logger.LogError("Initialisation error: {ErrorMessage}", result.ErrorMessage);
            Environment.Exit(1);
        }

        // Kick off the app and background workers
        logger.LogInformation("Starting application and background workers.");
        await host.RunAsync(CancellationToken.None);
    }
}
