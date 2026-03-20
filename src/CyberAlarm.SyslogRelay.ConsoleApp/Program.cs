using CyberAlarm.SyslogRelay.Domain;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.HealthCheck;
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

        using var scope = host.Services.CreateScope();
        var logger = scope.ServiceProvider.GetRequiredService<ILogger<IHost>>();

        // Run health checks if requested and exit
        if (HasFlag(args, "--health-check"))
        {
            await CheckHealth(scope, logger);
        }

        // Initialise relay and run checks
        await InitialiseApplication(scope, logger);

        // Kick off the app and background workers
        logger.LogInformation("Starting application and background workers.");
        await host.RunAsync(CancellationToken.None);
    }

    private static bool HasFlag(string[] args, string flag) =>
        args.Any(arg => string.Equals(arg, flag, StringComparison.OrdinalIgnoreCase));

    private static async Task CheckHealth(IServiceScope scope, ILogger logger)
    {
        var healthCheckService = scope.ServiceProvider.GetRequiredService<IHealthCheckService>();

        var result = await healthCheckService.CheckHealthAsync(CancellationToken.None);
        logger.LogInformation("Health status: {Status} [{Reason}]", result.Status, result.Reason);

        Environment.Exit(result.Status == HealthStatus.Healthy ? 0 : 1);
    }

    private static async Task InitialiseApplication(IServiceScope scope, ILogger logger)
    {
        var initialisationService = scope.ServiceProvider.GetRequiredService<InitialisationService>();

        var result = await initialisationService.InitialiseAsync(CancellationToken.None);
        if (result.IsFailed)
        {
            logger.LogError("Initialisation error: {ErrorMessage}", result.ErrorMessage);
            Environment.Exit(1);
        }
    }
}
