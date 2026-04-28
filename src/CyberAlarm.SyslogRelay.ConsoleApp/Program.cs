using System.Reflection;
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
using Serilog.Formatting.Compact;

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

        var buildVersion = ResolveBuildVersion(builder.Configuration);
        builder.Configuration["BuildVersion"] = buildVersion;

        if (OperatingSystem.IsWindows())
        {
            builder.AddWindowsPlatformSupport();
        }

        var logFilePath = builder.Configuration["SerilogFilePath"] ?? "logs/relay-.json";
        var isHealthCheck = HasFlag(args, "--health-check");

        builder.Services.AddSerilog((_, loggerConfiguration) =>
        {
            loggerConfiguration
                .ReadFrom.Configuration(builder.Configuration)
                .Enrich.FromLogContext()
                .Enrich.WithProperty("BuildVersion", buildVersion);

            if (!isHealthCheck)
            {
                loggerConfiguration.WriteTo.File(
                    new RenderedCompactJsonFormatter(),
                    logFilePath,
                    rollingInterval: Serilog.RollingInterval.Day,
                    retainedFileCountLimit: 7);
            }
        });

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
        var loggerFactory = scope.ServiceProvider.GetRequiredService<ILoggerFactory>();
        var logger = loggerFactory.CreateLogger("CyberAlarm.SyslogRelay");
        logger.LogInformation("Build number: {BuildNumber}", buildVersion);

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

    private static string ResolveBuildVersion(ConfigurationManager configuration)
    {
        var configuredBuildVersion = configuration["BuildVersion"];
        if (!string.IsNullOrWhiteSpace(configuredBuildVersion))
        {
            return configuredBuildVersion;
        }

        return Assembly.GetEntryAssembly()?.GetName().Version?.ToString() ?? "1.0.0";
    }

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
