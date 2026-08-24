using BenchmarkDotNet.Attributes;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Services;
using Microsoft.Extensions.Logging.Abstractions;

namespace CyberAlarm.SyslogRelay.Benchmarks;

/// <summary>
/// Benchmarks the NDJSON serialization + disk flush path used by BufferedPersistenceStage.
/// Each iteration writes 25 batches to separate temp files, giving ~100ms of total execution
/// time so BenchmarkDotNet can produce reliable statistics for this disk-I/O-bound operation.
/// </summary>
[MemoryDiagnoser]
public class PersistenceStageBenchmarks
{
    private const int BatchesPerInvocation = 25;

    private FileManager _fileManager = null!;
    private List<ParsedEvent> _batch1000 = [];
    private List<ParsedEvent> _batch100 = [];

    [Params(100, 1000)]
    public int BatchSize { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _fileManager = new FileManager(new PlatformService(), NullLogger<FileManager>.Instance);

        var events = Enumerable.Range(0, 1000)
            .Select(i => new ParsedEvent(
                Timestamp: DateTime.UtcNow,
                EventSource: new EventSource(IngestionMethod.File, "cisco-asa"),
                RawData: null,
                PatternName: "Cisco ASA",
                ParseResult: new ParseResult(
                    SourceIp: "192.0.2.1",
                    DestinationIp: "10.0.1.50",
                    SourcePort: 1024 + (i % 60000),
                    DestinationPort: 443,
                    Protocol: EventProtocol.Tcp,
                    Action: EventAction.Allow),
                ValidationStatus: ValidationStatus.Success))
            .ToList();

        _batch1000 = events;
        _batch100 = events.Take(100).ToList();
    }

    [Benchmark(OperationsPerInvoke = BatchesPerInvocation)]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1707", Justification = "BenchmarkDotNet convention")]
    public async Task Write_Batch()
    {
        var batch = BatchSize == 1000 ? _batch1000 : _batch100;

        for (var i = 0; i < BatchesPerInvocation; i++)
        {
            var path = Path.Combine(Path.GetTempPath(), $"bm-persist-{Guid.NewGuid()}.log");
            await _fileManager.AppendAndSaveItemsAsNdjson(batch, path, CancellationToken.None);
            File.Delete(path);
        }
    }
}
