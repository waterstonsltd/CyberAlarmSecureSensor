using System.Net;
using System.Text.Json;
using CyberAlarm.SyslogRelay.Common.Status.Models;
using CyberAlarm.SyslogRelay.Domain.Diagnostics;
using CyberAlarm.SyslogRelay.Domain.Pipeline;
using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Domain.State;
using CyberAlarm.SyslogRelay.Domain.Upload.Scheduling;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class DiagnosticsServiceBuilder : IDisposable
{
    private readonly string _tempDir = Path.Combine(Path.GetTempPath(), "ca-diag-tests-" + Guid.NewGuid().ToString("N"));
    private readonly TestHttpClientMessageHandler _httpHandler;

    public DiagnosticsServiceBuilder()
    {
        Directory.CreateDirectory(_tempDir);

        _httpHandler = new TestHttpClientMessageHandler(() => new HttpResponseMessage(HttpStatusCode.OK));
        var httpClient = new HttpClient(_httpHandler);
        HttpClientFactory = Substitute.For<IHttpClientFactory>();
        HttpClientFactory.CreateClient(Arg.Any<string>()).Returns(httpClient);

        FileManager = Substitute.For<IFileManager>();
        FileManager.GetDataPath().Returns(_tempDir);
        FileManager.GetLogsFolder().Returns(Path.Combine(_tempDir, ".tmp", "logs"));
        FileManager.GetProcessingFolder().Returns(Path.Combine(_tempDir, ".tmp", "processing"));
        FileManager.GetSourceGroupFolder().Returns(Path.Combine(_tempDir, ".tmp", "source-groups"));
        FileManager.GetUploadFolder().Returns(Path.Combine(_tempDir, ".tmp", "upload"));
        FileManager.GetFailedFolder().Returns(Path.Combine(_tempDir, ".tmp", "failed"));
        FileManager.GetTemporaryFolder().Returns(Path.Combine(_tempDir, ".tmp", "temporaryFiles"));
        FileManager.ListFilesInDirectory(Arg.Any<string>()).Returns([]);
        FileManager.ListDirectoryNamesInDirectory(Arg.Any<string>()).Returns([]);

        FileManager.DeserialiseFromFileAsync<RelayState>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new RelayStateBuilder().Build());
        FileManager.DeserialiseFromFileAsync<RelayStatus>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new RelayStatusBuilder().Build());
        FileManager.DeserialiseFromFileAsync<Dictionary<string, JsonElement?>>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(default(Dictionary<string, JsonElement?>));

        PlatformService = Substitute.For<IPlatformService>();
        PlatformService.GetPlatform().Returns(new Platform("TestOS 1.0", ".NET 10", "x64", false));
        PlatformService.GetPlatformType().Returns(PlatformType.Linux);

        RelayOptions = new RelayOptionsBuilder().Build();
        PipelineOptions = new PipelineOptions();
        ScheduleOptions = new ScheduleOptions();
    }

    public string TempDir => _tempDir;

    public IFileManager FileManager { get; }

    public IPlatformService PlatformService { get; }

    public IHttpClientFactory HttpClientFactory { get; }

    public RelayOptions RelayOptions { get; }

    public PipelineOptions PipelineOptions { get; }

    public ScheduleOptions ScheduleOptions { get; }

    public DiagnosticsServiceBuilder WithState(RelayState? state)
    {
        FileManager.DeserialiseFromFileAsync<RelayState>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(state);
        return this;
    }

    public DiagnosticsServiceBuilder WithStatus(RelayStatus? status)
    {
        FileManager.DeserialiseFromFileAsync<RelayStatus>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(status);
        return this;
    }

    public DiagnosticsServiceBuilder WithHealthData(Dictionary<string, JsonElement?>? data)
    {
        // File.Exists() must return true for the health data branch to be reached
        File.WriteAllText(Path.Combine(_tempDir, "healthcheck.json"), "{}");
        FileManager.DeserialiseFromFileAsync<Dictionary<string, JsonElement?>>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(data);
        return this;
    }

    public DiagnosticsService Build() =>
        new(
            FileManager,
            PlatformService,
            Options.Create(RelayOptions),
            Options.Create(PipelineOptions),
            Options.Create(ScheduleOptions),
            HttpClientFactory,
            new ConfigurationBuilder().Build());

    public void Dispose()
    {
        _httpHandler.Dispose();

        try
        {
            Directory.Delete(_tempDir, recursive: true);
        }
        catch (IOException)
        {
            // best-effort cleanup
        }
    }
}
