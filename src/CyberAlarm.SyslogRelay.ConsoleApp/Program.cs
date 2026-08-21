using System.Reflection;
using CyberAlarm.SyslogRelay.Domain;
using CyberAlarm.SyslogRelay.Domain.Diagnostics;
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
        Microsoft.Extensions.Logging.ILogger? logger = null;

        try
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

            // Re-add user secrets after platform-specific config so they take
            // precedence over appsettings.windows.local.json during local development.
            if (builder.Environment.IsDevelopment())
            {
                builder.Configuration.AddUserSecrets(Assembly.GetExecutingAssembly());
            }

            var logFilePath = builder.Configuration["SerilogFilePath"] ?? "logs/relay-.json";
            var isHealthCheck = HasFlag(args, "--health-check");
            var isSingleShotCommand = isHealthCheck
                || HasFlag(args, "--diagnostics")
                || HasFlag(args, "--support-bundle");

            builder.Services.AddSerilog((_, loggerConfiguration) =>
            {
                loggerConfiguration
                    .ReadFrom.Configuration(builder.Configuration)
                    .Enrich.FromLogContext()
                    .Enrich.WithProperty("BuildVersion", buildVersion);

                if (!isSingleShotCommand)
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
            logger = loggerFactory.CreateLogger("CyberAlarm.SyslogRelay");
            logger.LogInformation("Build number: {BuildNumber}", buildVersion);
            var appManager = (ApplicationManager)scope.ServiceProvider.GetRequiredService<IApplicationManager>();
            var lifetime = host.Services.GetRequiredService<IHostApplicationLifetime>();
            lifetime.ApplicationStopping.Register(() =>
                logger.LogInformation("Application stopping. Reason: {ShutdownReason}", appManager.ShutdownReason));

            if (HasFlag(args, "--health-check"))
            {
                await CheckHealth(scope, logger);
            }

            if (HasFlag(args, "--diagnostics"))
            {
                await RunDiagnostics(scope, args);
            }

            if (HasFlag(args, "--support-bundle"))
            {
                await RunSupportBundle(scope);
            }

            await InitialiseApplication(scope, logger);

            logger.LogInformation("Starting application and background workers.");
            await host.RunAsync(CancellationToken.None);
        }
        catch (Exception ex)
        {
            if (logger is not null)
            {
                logger.LogCritical(ex, "Application terminated unexpectedly during startup or host execution.");
            }
            else
            {
                await Console.Error.WriteLineAsync($"Fatal startup error: {ex}");
            }

            throw;
        }
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

    private static async Task RunDiagnostics(IServiceScope scope, string[] args)
    {
        var verbose = HasFlag(args, "--full");
        var diagnosticsService = scope.ServiceProvider.GetRequiredService<DiagnosticsService>();
        await diagnosticsService.RunAsync(Console.Out, verbose, CancellationToken.None);
        Environment.Exit(0);
    }

    private static async Task RunSupportBundle(IServiceScope scope)
    {
        var bundleService = scope.ServiceProvider.GetRequiredService<SupportBundleService>();
        try
        {
            var zipPath = await bundleService.CreateBundleAsync(CancellationToken.None);
            Console.WriteLine();
            Console.WriteLine($"Support bundle saved to: {zipPath}");
            Console.WriteLine("Please send this file to your CyberAlarm support contact or attach it to your support ticket.");
            Console.WriteLine();
            Environment.Exit(0);
        }
        catch (InvalidOperationException ex)
        {
            await Console.Error.WriteLineAsync();
            await Console.Error.WriteLineAsync($"Error: {ex.Message}");
            await Console.Error.WriteLineAsync();
            Environment.Exit(1);
        }
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
