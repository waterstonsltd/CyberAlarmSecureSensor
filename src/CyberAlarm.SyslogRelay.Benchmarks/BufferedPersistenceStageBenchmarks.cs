using BenchmarkDotNet.Attributes;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.HealthCheck;
using CyberAlarm.SyslogRelay.Domain.Pipeline;
using CyberAlarm.SyslogRelay.Domain.Pipeline.Stages;
using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Tests.Common;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace CyberAlarm.SyslogRelay.Benchmarks;

/// <summary>
/// Benchmarks <see cref="BufferedPersistenceStage"/> end-to-end:
/// event mapping, buffer accumulation, flush-queue hand-off, and NDJSON disk write.
///
/// Each iteration enqueues <see cref="EventCount"/> events then stops the stage,
/// which flushes any remaining buffer. The stage is rebuilt per iteration so the
/// buffer state is always clean.
/// </summary>
[MemoryDiagnoser]
public class BufferedPersistenceStageBenchmarks
{
    private string _tempLogsPath = string.Empty;
    private ValidationStageOutput[] _events = [];
    private IFileManager _fileManager = null!;

    [Params(100, 1000)]
    public int EventCount { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _tempLogsPath = Path.Combine(Path.GetTempPath(), $"bm-persistence-{Guid.NewGuid()}");
        Directory.CreateDirectory(_tempLogsPath);

        var platformService = new PlatformService();
        var fileManager = new FileManager(platformService, NullLogger<FileManager>.Instance);

        // Redirect GetLogsFolder() to our temp directory via a thin wrapper.
        _fileManager = new RedirectedFileManager(fileManager, _tempLogsPath);

        var parseResult = new ParseResult("192.0.2.1", "10.0.1.50", 1234, 443, EventProtocol.Tcp, EventAction.Allow);
        var patternMatch = new PatternMatchResult("Cisco ASA", Substitute.For<IParser>());
        var validationResult = new ValidationResult(ValidationStatus.Success);

        _events = Enumerable.Range(0, 1000)
            .Select(i => new ValidationStageOutput(
                SyslogEvent.FromFile("cisco-asa", $"<166>{i}: %ASA-6-106015: raw log line {i}"),
                patternMatch,
                parseResult,
                validationResult))
            .ToArray();
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        if (Directory.Exists(_tempLogsPath))
        {
            Directory.Delete(_tempLogsPath, recursive: true);
        }
    }

    [Benchmark(OperationsPerInvoke = 1)]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1707", Justification = "BenchmarkDotNet convention")]
    public async Task Enqueue_And_Flush()
    {
        var stage = BuildStage(bufferSize: EventCount);

        await stage.StartAsync(CancellationToken.None);

        for (var i = 0; i < EventCount; i++)
        {
            await stage.EnqueueAsync(_events[i], CancellationToken.None);
        }

        // StopAsync flushes remaining buffer and drains writer tasks.
        await stage.StopAsync(CancellationToken.None);
    }

    private BufferedPersistenceStage BuildStage(int bufferSize)
    {
        var healthToken = Substitute.For<IHealthToken>();
        healthToken.HealthyAsync(Arg.Any<CancellationToken>()).Returns(Task.CompletedTask);
        healthToken.UnhealthyAsync(Arg.Any<CancellationToken>()).Returns(Task.CompletedTask);
        healthToken.UnregisterAsync(Arg.Any<CancellationToken>()).Returns(Task.CompletedTask);

        var healthCheckService = Substitute.For<IHealthCheckService>();
        healthCheckService.GetHealthToken(Arg.Any<string>()).Returns(healthToken);

        var options = new PipelineOptions
        {
            PersistenceBufferSize = bufferSize,
            PersistenceBufferIntervalInSeconds = 3600, // disable time-based flush
            ChannelCapacity = 10_000,
        };

        var services = new PipelineStageServices(
            Substitute.For<IApplicationManager>(),
            healthCheckService,
            Options.Create(options),
            new PipelineMetrics(new TestMeterFactory()));

        var periodicOperation = Substitute.For<IPeriodicOperation>();
        periodicOperation.StopAsync().Returns(Task.CompletedTask);

        return new BufferedPersistenceStage(
            _fileManager,
            periodicOperation,
            services,
            NullLogger<BufferedPersistenceStage>.Instance);
    }

    /// <summary>
    /// Forwards all <see cref="IFileManager"/> calls to the real implementation, but
    /// overrides <see cref="GetLogsFolder"/> to return a benchmark-controlled temp path.
    /// </summary>
    private sealed class RedirectedFileManager(IFileManager inner, string logsPath) : IFileManager
    {
        public string GetLogsFolder() => logsPath;

        public bool CanWriteFile(string filePath) => inner.CanWriteFile(filePath);
        public bool Exists(string path) => inner.Exists(path);
        public string GetDataPath() => inner.GetDataPath();
        public string GetEventsMetaDataFilePath() => inner.GetEventsMetaDataFilePath();
        public string GetProcessingFolder() => inner.GetProcessingFolder();
        public string GetSourceGroupFolder() => inner.GetSourceGroupFolder();
        public string GetUploadFolder() => inner.GetUploadFolder();
        public string GetFailedFolder() => inner.GetFailedFolder();
        public string GetTemporaryFolder() => inner.GetTemporaryFolder();
        public Task<T?> DeserialiseFromFileAsync<T>(string filePath, CancellationToken cancellationToken) => inner.DeserialiseFromFileAsync<T>(filePath, cancellationToken);
        public Task SerialiseToFileAsync<T>(T value, string filePath, CancellationToken cancellationToken) => inner.SerialiseToFileAsync(value, filePath, cancellationToken);
        public Task AppendAndSaveItemsAsNdjson<T>(IEnumerable<T> items, string filePath, CancellationToken cancellationToken) => inner.AppendAndSaveItemsAsNdjson(items, filePath, cancellationToken);
        public Task<IEnumerable<T>> DeserialiseFromNdjson<T>(string filePath, CancellationToken cancellationToken) => inner.DeserialiseFromNdjson<T>(filePath, cancellationToken);
        public Task<byte[]?> LoadFromFileAsync(string filePath, CancellationToken cancellationToken) => inner.LoadFromFileAsync(filePath, cancellationToken);
        public Task SaveToFileAsync(byte[] value, string filePath, CancellationToken cancellationToken) => inner.SaveToFileAsync(value, filePath, cancellationToken);
        public Stream OpenStreamFromFile(string filePath, CancellationToken cancellationToken) => inner.OpenStreamFromFile(filePath, cancellationToken);
        public Stream OpenWriteStreamForFile(string filePath, CancellationToken cancellationToken) => inner.OpenWriteStreamForFile(filePath, cancellationToken);
        public IEnumerable<string> ListDirectoryNamesInDirectory(string directoryPath) => inner.ListDirectoryNamesInDirectory(directoryPath);
        public IEnumerable<string> ListFileNamesInDirectory(string directoryPath) => inner.ListFileNamesInDirectory(directoryPath);
        public IEnumerable<string> ListFilesInDirectory(string directoryPath) => inner.ListFilesInDirectory(directoryPath);
        public void Move(string sourceFilePath, string destinationFilePath) => inner.Move(sourceFilePath, destinationFilePath);
        public void Delete(string filePath) => inner.Delete(filePath);
        public void CreateEmptyFile(string filePath) => inner.CreateEmptyFile(filePath);
        public long GetFileSize(string file) => inner.GetFileSize(file);
    }
}
