using CyberAlarm.EventBundler.Plugins.Compressors;
using CyberAlarm.EventBundler.Plugins.Encryptors;
using CyberAlarm.EventBundler.Plugins.Signers;
using CyberAlarm.EventBundler.Services;
using CyberAlarm.SyslogRelay.Common.EventBundler.Plugins;
using CyberAlarm.SyslogRelay.Domain.Ingestion;
using CyberAlarm.SyslogRelay.Domain.Initialisation;
using CyberAlarm.SyslogRelay.Domain.Parsing;
using CyberAlarm.SyslogRelay.Domain.Parsing.Cisco;
using CyberAlarm.SyslogRelay.Domain.Pipeline;
using CyberAlarm.SyslogRelay.Domain.Pipeline.Stages;
using CyberAlarm.SyslogRelay.Domain.Registration;
using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Domain.State;
using CyberAlarm.SyslogRelay.Domain.Status;
using CyberAlarm.SyslogRelay.Domain.Upload.Infrastructure;
using CyberAlarm.SyslogRelay.Domain.Upload.Scheduling;
using CyberAlarm.SyslogRelay.Domain.Upload.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Polly;
using Polly.Extensions.Http;

namespace CyberAlarm.SyslogRelay.Domain;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddDomainServices(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddTransient<IPeriodicOperation, PeriodicOperation>();
        services.AddTransient<IPlatformService, PlatformService>();

        services.AddScoped<ETagHandler>();
        services.AddScoped<InitialisationService>()
            .AddTransient<IStartupActivity, CheckWriteAccessActivity>()
            .AddTransient<IStartupActivity, CheckConfigurationActivity>()
            .AddTransient<IStartupActivity, LoadStateActivity>()
            .AddTransient<IStartupActivity, FetchStatusActivity>()
            .AddTransient<IStartupActivity, RegistrationActivity>()
            .AddTransient<IStartupActivity, DeleteTemporaryFiles>();

        services.AddScoped<IRegistrationClient, RegistrationClient>();
        services.AddScoped<IRegistrationService, RegistrationService>();

        services.AddSingleton<IFileSelector, FileSelector>();
        services.AddSingleton<ISourceGrouper, SourceGrouper>();
        services.AddSingleton<IFileBundler, FileBundler>();
        services.AddSingleton<ISecureUploader, SecureUploader>();
        services.AddSingleton<ISecureFtpClientFactory, SecureFtpClientFactory>();

        services.AddSingleton<IFileManager, FileManager>();
        services.AddSingleton<IRsaKeyProvider, RsaKeyProvider>();
        services.AddSingleton<IStateService, StateService>()
            .Decorate<IStateService, CachedStateService>();
        services.AddSingleton<IStatusClient, StatusClient>();
        services.AddSingleton<IStatusService, StatusService>()
            .Decorate<IStatusService, CachedStatusService>();
        services.AddSingleton(TimeProvider.System);

        services.AddSingleton<FileWatcher>();
        services.AddSingleton<TcpListener>();
        services.AddSingleton<UdpListener>();
        services.AddSingleton<IParserFactory, ParserFactory>()
            .AddTransient<IParser, CiscoAsaParser>();
        services.AddSingleton(provider =>
            PipelineBuilder
                .StartWith(provider => provider.GetRequiredService<PatternMatchingStage>())
                .Then(provider => provider.GetRequiredService<ParsingStage>())
                .Then(provider => provider.GetRequiredService<BufferedPersistenceStage>())
                .Build(provider))
            .AddTransient<PatternMatchingStage>()
            .AddTransient<ParsingStage>()
            .AddTransient<BufferedPersistenceStage>();

        services.Configure<PipelineOptions>(configuration);
        services.Configure<RelayOptions>(configuration);

        services.AddHttpClient(nameof(RegistrationClient))
            .AddPolicyHandler(HttpPolicyExtensions
            .HandleTransientHttpError()
            .WaitAndRetryAsync(5, retry => TimeSpan.FromSeconds(retry)));
        services.AddHttpClient(nameof(StatusClient))
            .AddHttpMessageHandler<ETagHandler>();

        return services;
    }

    public static IServiceCollection AddEventBundlerServices(this IServiceCollection services)
    {
        services.AddTransient<ISigner, RsaPssSha256Signer>();
        services.AddTransient(sp => sp.GetServices<ISigner>().ToArray());
        services.AddTransient<ICompressor, BrotliCompressor>();
        services.AddTransient(sp => sp.GetServices<ICompressor>().ToArray());
        services.AddTransient<IAsymmetricEncryptor, RsaOaepSha256AsymmetricEncryptor>();
        services.AddTransient(sp => sp.GetServices<IAsymmetricEncryptor>().ToArray());
        services.AddTransient<ISymmetricEncryptor, Aes256GcmSymmetricEncryptor>();
        services.AddTransient(sp => sp.GetServices<ISymmetricEncryptor>().ToArray());
        services.AddTransient<IEventBundlerService, EventBundlerService>();
        services.AddTransient<IEventPackerService, EventPackerService>();
        services.AddTransient<IPluginFactory<ISigner>, PluginFactory<ISigner>>();
        services.AddTransient<IPluginFactory<ICompressor>, PluginFactory<ICompressor>>();
        services.AddTransient<IPluginFactory<IAsymmetricEncryptor>, PluginFactory<IAsymmetricEncryptor>>();
        services.AddTransient<IPluginFactory<ISymmetricEncryptor>, PluginFactory<ISymmetricEncryptor>>();

        return services;
    }

    public static IServiceCollection AddScheduledServices(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddTransient<IScheduler, Scheduler>();
        services.AddTransient<Func<TimeSpan, IPeriodicTimer>>(_ =>
        {
            return timeSpan => new StandardPeriodicTimer(timeSpan);
        });

        services.Configure<ScheduleOptions>(configuration);

        return services;
    }
}
