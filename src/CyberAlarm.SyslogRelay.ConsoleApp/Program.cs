using CyberAlarm.SyslogRelay.Domain;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.HealthCheck;
using CyberAlarm.SyslogRelay.Domain.Initialisation;
using CyberAlarm.SyslogRelay.Domain.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Serilog;

namespace CyberAlarm.SyslogRelay.ConsoleApp;

using ILogger = Microsoft.Extensions.Logging.ILogger;

internal static class Program
{
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static void Main(string[] args)
    {
        if (OperatingSystem.IsWindows())
        {
            WindowsHost.RunVelopackHooks();
        }

        RunAsync(args).GetAwaiter().GetResult();
    }

    private static async Task RunAsync(string[] args)
    {
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
        {
            Args = args,
            ContentRootPath = AppContext.BaseDirectory,
        });

        if (OperatingSystem.IsWindows())
        {
            builder.AddWindowsPlatformSupport();
        }
        else
        {
            builder.Configuration.AddJsonFile("appsettings.linux.json", optional: true, reloadOnChange: true);
        }

        builder.Services.AddSerilog((_, loggerConfiguration) =>
            loggerConfiguration.ReadFrom.Configuration(builder.Configuration).Enrich.FromLogContext());

        builder.Services
            .AddMetrics()
            .AddDomainServices(builder.Configuration)
            .AddEventBundlerServices()
            .AddScheduledServices(builder.Configuration)
            .AddHostedService<UploadService>()
            .AddHostedService<IngestionService>();

        builder.Services.AddSingleton<IApplicationManager, ApplicationManager>();

        var host = builder.Build();

        using var scope = host.Services.CreateScope();
        var logger = scope.ServiceProvider.GetRequiredService<ILogger<IHost>>();
        logger.LogInformation("Build number: {BuildNumber}", builder.Configuration["BuildVersion"] ?? "unknown");

        if (HasFlag(args, "--health-check"))
        {
            await CheckHealth(scope, logger);
        }

        await InitialiseApplication(scope, logger);

        logger.LogInformation("Starting application and background workers.");
        await host.RunAsync(CancellationToken.None);
    }

    private static bool HasFlag(string[] args, string flag) =>
        args.Any(arg => string.Equals(arg, flag, StringComparison.OrdinalIgnoreCase));

    private static async Task CheckHealth(IServiceScope scope, Microsoft.Extensions.Logging.ILogger logger)
    {
        var healthCheckService = scope.ServiceProvider.GetRequiredService<IHealthCheckService>();
        var result = await healthCheckService.CheckHealthAsync(CancellationToken.None);
        logger.LogInformation("Health status: {Status} [{Reason}]", result.Status, result.Reason);
        Environment.Exit(result.Status == HealthStatus.Healthy ? 0 : 1);
    }

    private static async Task InitialiseApplication(IServiceScope scope, Microsoft.Extensions.Logging.ILogger logger)
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
