using System.Diagnostics;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Text.Json;
using CyberAlarm.SyslogRelay.Domain.Ingestion;
using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Tests.Common;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using Xunit.Abstractions;
using static CyberAlarm.SyslogRelay.Domain.Tests.Ingestion.RawExportTestData;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Ingestion;

public sealed class RawExportIngestionReaderTests(ITestOutputHelper output)
{
    private readonly IFileManager _fileManager = Substitute.For<IFileManager>();
    private readonly ILogger<RawExportIngestionReader> _logger = Substitute.For<ILogger<RawExportIngestionReader>>();
    private readonly FakeTimeProvider _timeProvider = new();

    [Fact]
    public void Replay_decode_cost_for_ordinary_syslog_payloads()
    {
        const int records = 50_000;
        for (var i = 0; i < 100; i++)
        {
            RawExportReader.Decode(Example, 1);
        }

        var thread = Environment.CurrentManagedThreadId;
        var exceptions = 0;
        void CountException(object? sender, FirstChanceExceptionEventArgs args)
        {
            if (Environment.CurrentManagedThreadId == thread && args.Exception is JsonException)
            {
                exceptions++;
            }
        }

        AppDomain.CurrentDomain.FirstChanceException += CountException;
        var allocated = GC.GetAllocatedBytesForCurrentThread();
        var stopwatch = Stopwatch.StartNew();
        try
        {
            for (var i = 0; i < records; i++)
            {
                Assert.Equal(Expected, RawExportReader.Decode(Example, i + 1));
            }
        }
        finally
        {
            stopwatch.Stop();
            allocated = GC.GetAllocatedBytesForCurrentThread() - allocated;
            AppDomain.CurrentDomain.FirstChanceException -= CountException;
        }

        output.WriteLine($"Decode: {records} records, {stopwatch.Elapsed.TotalSeconds:F3}s, {allocated / records} allocated bytes/record, {exceptions} JSON exceptions.");
        Assert.Equal(0, exceptions);
        Assert.True(allocated / records < 1_500, "Replay decoding should not allocate redundant UTF-8 buffers or property arrays.");
    }

    [Fact]
    public void Replay_defaults_off_and_binds_from_configuration()
    {
        Assert.False(new RelayOptions().FileWatcherReplayRawExports);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["FileWatcherReplayRawExports"] = "true",
        }).Build();
        Assert.True(configuration.Get<RelayOptions>()!.FileWatcherReplayRawExports);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Domain_registration_selects_reader_from_replay_configuration(bool? replay)
    {
        Setup(Example);
        var settings = new Dictionary<string, string?>();
        if (replay.HasValue)
        {
            settings["FileWatcherReplayRawExports"] = replay.Value.ToString();
        }

        var configuration = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDomainServices(configuration);
        services.AddSingleton(_fileManager);
        using var provider = services.BuildServiceProvider();
        var reader = provider.GetRequiredService<IFileIngestionReader>();
        if (replay is true)
        {
            Assert.IsType<RawExportIngestionReader>(reader);
        }
        else
        {
            Assert.IsType<FileIngestionReader>(reader);
        }

        Assert.Equal(replay is true ? Expected : Example, Assert.Single(await ReadAllAsync(reader)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Example_is_decoded_only_when_replay_is_enabled(bool enabled)
    {
        var reader = Setup("\n \n" + Example + "\n", enabled);
        Assert.Equal(enabled ? Expected : Example, Assert.Single(await ReadAllAsync(reader)));
        foreach (var prefix in new[] { "Checking file ", "Raw export validation completed ", "Replayed 1 raw records " })
        {
            var messages = _logger.ReceivedLogs()
                .Where(log => log.Item2?.StartsWith(prefix, StringComparison.Ordinal) == true).ToArray();
            Assert.Equal(enabled ? 1 : 0, messages.Length);
            Assert.All(messages, log => Assert.Equal(LogLevel.Debug, log.Item1));
        }

        Assert.DoesNotContain(_logger.ReceivedLogs(), log => log.Item1 == LogLevel.Information);
    }

    [Theory]
    [InlineData("<134>ordinary syslog")]
    [InlineData("""{"message":"native JSON","RawData":"not a CyberAlarm export"}""")]
    [InlineData("""{"Timestamp":"2026-09-14","message":"native JSON"}""")]
    [InlineData("""{"nested":{"Timestamp":"old","PatternName":"test","ParseResult":null},"RawData":"native JSON"}""")]
    [InlineData("{malformed native log")]
    public async Task Ordinary_logs_remain_unchanged_when_enabled(string raw)
    {
        var reader = Setup(raw + "\nsecond ordinary line");
        Assert.Equal(new[] { raw, "second ordinary line" }, await ReadAllAsync(reader));
        _fileManager.Received(1).OpenStreamFromFile("capture.log", CancellationToken.None);
        Assert.DoesNotContain(_logger.ReceivedLogs(), log => log.Item2?.StartsWith("Replayed ", StringComparison.Ordinal) == true);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Fallback_rewinds_the_same_file_and_preserves_byte_order_marks(bool utf16)
    {
        const string content = "\nfirst ordinary line\n \nsecond ordinary line\n";
        var reader = Setup(content);
        Encoding encoding = utf16 ? Encoding.Unicode : new UTF8Encoding(true);
        var stream = new MemoryStream(encoding.GetPreamble().Concat(encoding.GetBytes(content)).ToArray());
        _fileManager.OpenStreamFromFile(Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(stream);
        Assert.Collection(await ReadAllAsync(reader),
            line => Assert.Equal("first ordinary line", line),
            line => Assert.Equal("second ordinary line", line));
        _fileManager.Received(1).OpenStreamFromFile("capture.log", CancellationToken.None);
        Assert.False(stream.CanRead);
    }

    [Theory]
    [InlineData("")]
    [InlineData("\n \n\t\n")]
    public async Task Empty_files_yield_no_events(string content)
    {
        Assert.Empty(await ReadAllAsync(Setup(content)));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(8)]
    public async Task Previously_wrapped_exports_reach_the_original_raw_log(int layers)
    {
        const string original = "<30>Feb 11 11:48:09 charon[64961]: 05[IKE] <con1|18> nothing to initiate";
        var line = """{"Timestamp":"2026-09-11T14:57:27.2121958Z","RawData":"\u003C30\u003EFeb 11 11:48:09 charon[64961]: 05[IKE] \u003Ccon1|18\u003E nothing to initiate","PatternName":"Unknown","ValidationStatus":"UnableToParse"}""";
        for (var layer = 1; layer < layers; layer++)
        {
            line = Export(line);
        }

        Assert.Equal(original, Assert.Single(await ReadAllAsync(Setup(line))));
    }

    [Fact]
    public async Task Nested_native_json_is_not_unwrapped_or_unescaped_again()
    {
        const string original = """{"message":"literal \\u003C","RawData":"native firewall field"}""";
        Assert.Equal(original, Assert.Single(await ReadAllAsync(Setup(Export(Export(original))))));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Invalid_or_excessively_nested_exports_fail_before_yielding_any_records(bool excessive)
    {
        var nested = excessive
            ? "original syslog"
            : """{"Timestamp":"old","PatternName":"Unknown","ParseResult":null,"RawData":null}""";
        for (var layer = 0; layer < (excessive ? 9 : 1); layer++)
        {
            nested = Export(nested);
        }

        var reader = Setup(Example + "\n" + nested);
        await using var records = reader.ReadAsync("capture.log", CancellationToken.None).GetAsyncEnumerator();
        var exception = await Assert.ThrowsAsync<InvalidDataException>(async () => await records.MoveNextAsync());
        Assert.Contains("line 2", exception.Message);
        if (excessive)
        {
            Assert.Contains("more than 8", exception.Message);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Both_passes_handle_export_byte_order_marks(bool utf16)
    {
        var reader = Setup(Example);
        Encoding encoding = utf16 ? Encoding.Unicode : new UTF8Encoding(true);
        var bytes = encoding.GetPreamble().Concat(encoding.GetBytes(Example)).ToArray();
        _fileManager.OpenStreamFromFile(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(_ => new MemoryStream(bytes));
        Assert.Equal(Expected, Assert.Single(await ReadAllAsync(reader)));
    }

    [Fact]
    public async Task Escaped_newlines_remain_inside_a_single_raw_event()
    {
        const string raw = "first\r\nsecond\t\"quote\"\\end";
        Assert.Equal(raw, Assert.Single(await ReadAllAsync(Setup(Export(raw)))));
    }

    [Theory]
    [InlineData("""{"Timestamp":"old","PatternName":"test","ParseResult":null}""")]
    [InlineData("""{"Timestamp":"old","PatternName":"test","ParseResult":null,"RawData":null}""")]
    [InlineData("""{"Timestamp":"old","PatternName":"test","ParseResult":null,"RawData":42}""")]
    [InlineData("""{"Timestamp":"old","PatternName":"test","ParseResult":null,"RawData":{}}""")]
    [InlineData("""{"Timestamp":"old","PatternName":"test","ParseResult":null,"RawData":" "}""")]
    [InlineData("""{"Timestamp":"old","PatternName":"test","ParseResult":null,"RawData":"a","RawData":"b"}""")]
    [InlineData("""{"Timestamp":"old","PatternName":"test","ParseResult":null,"RawData":"customer-secret","broken":""")]
    public async Task Invalid_first_export_throws_and_disposes_the_stream(string line)
    {
        var reader = Setup(line);
        var stream = new MemoryStream(Encoding.UTF8.GetBytes(line));
        _fileManager.OpenStreamFromFile(Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(stream);
        var exception = await Assert.ThrowsAsync<InvalidDataException>(() => ReadAllAsync(reader));
        Assert.Contains("line 1", exception.Message);
        Assert.DoesNotContain("customer-secret", exception.ToString());
        Assert.Null(exception.InnerException);
        Assert.False(stream.CanRead);
    }

    [Theory]
    [InlineData("{broken customer-secret")]
    [InlineData("ordinary syslog in an export file")]
    [InlineData("""{"Timestamp":"old","PatternName":null,"ParseResult":null}""")]
    public async Task Invalid_later_record_fails_before_any_records_are_yielded(string invalid)
    {
        var reader = Setup(Example + "\n\n" + invalid);
        await using var records = reader.ReadAsync("capture.log", CancellationToken.None).GetAsyncEnumerator();
        var exception = await Assert.ThrowsAsync<InvalidDataException>(async () => await records.MoveNextAsync());
        Assert.Contains("line 3", exception.Message);
        Assert.DoesNotContain("customer-secret", exception.ToString());
        Assert.Null(exception.InnerException);
    }

    [Fact]
    public async Task Enumeration_cancellation_is_observed_before_opening_the_file()
    {
        var reader = Setup(Example);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
        {
            await foreach (var unused in reader.ReadAsync("capture.log", CancellationToken.None).WithCancellation(cancellation.Token))
            {
                Assert.Fail("A cancelled reader must not yield records.");
            }
        });
        _fileManager.DidNotReceive().OpenStreamFromFile(Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Cancellation_between_records_disposes_the_stream(bool replay)
    {
        var reader = Setup(Example + "\n" + Example, replay);
        var stream = new MemoryStream(Encoding.UTF8.GetBytes(Example + "\n" + Example));
        _fileManager.OpenStreamFromFile(Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(stream);
        using var cancellation = new CancellationTokenSource();
        await using var records = reader.ReadAsync("capture.log", cancellation.Token).GetAsyncEnumerator();
        Assert.True(await records.MoveNextAsync());
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await records.MoveNextAsync());
        Assert.False(stream.CanRead);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Stream_is_disposed_after_completion_or_early_exit(bool exitEarly)
    {
        var reader = Setup(Example + "\n" + Example);
        var stream = new MemoryStream(Encoding.UTF8.GetBytes(Example + "\n" + Example));
        _fileManager.OpenStreamFromFile(Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(stream);
        var count = 0;
        await foreach (var raw in reader.ReadAsync("capture.log", CancellationToken.None))
        {
            Assert.Equal(Expected, raw);
            count++;
            if (exitEarly)
            {
                break;
            }
        }

        Assert.Equal(exitEarly ? 1 : 2, count);
        Assert.False(stream.CanRead);
        Assert.Equal(exitEarly ? 0 : 1, _logger.ReceivedLogs().Count(log => log.Item2?.StartsWith("Replayed ", StringComparison.Ordinal) == true));
    }

    [Fact]
    public async Task Preflight_observes_cancellation()
    {
        using var reader = new StreamReader(new MemoryStream(Encoding.UTF8.GetBytes(Example)));
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => RawExportReader.ValidateAsync(reader, cancellation.Token));
    }

    [Fact]
    public async Task Preflight_reports_validated_records_without_counting_blank_lines()
    {
        using var reader = new StreamReader(new MemoryStream(Encoding.UTF8.GetBytes("\n" + Example + "\n \n" + Example)));
        var progress = new List<long>();
        Assert.True(await RawExportReader.ValidateAsync(reader, CancellationToken.None, progress.Add));
        Assert.Equal(new long[] { 1, 2 }, progress);
    }

    [Fact]
    public async Task Many_export_records_are_replayed_in_order()
    {
        var lines = Enumerable.Range(0, 20_000).Select(i => Export($"event {i}"));
        var reader = Setup(string.Join("\n", lines));
        var count = 0;
        await foreach (var raw in reader.ReadAsync("capture.log", CancellationToken.None))
        {
            Assert.Equal($"event {count}", raw);
            count++;
        }

        Assert.Equal(20_000, count);
    }

    [Fact]
    public async Task Progress_is_reported_at_ten_seconds_independently_for_each_phase()
    {
        var content = string.Concat(Enumerable.Repeat(Example + "\n", 3));
        var reader = Setup(content);
        _fileManager.OpenStreamFromFile(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(_ => new AdvancingStream(Encoding.UTF8.GetBytes(content), Encoding.UTF8.GetByteCount(Example + "\n"), _timeProvider));
        Assert.Equal(3, (await ReadAllAsync(reader)).Count);
        var progress = _logger.ReceivedLogs().Where(log => log.Item1 == LogLevel.Information).ToArray();
        Assert.Equal(2, progress.Length);
        Assert.StartsWith("Validating raw export 'capture.log': 2 records", progress[0].Item2);
        Assert.StartsWith("Replaying raw export 'capture.log': 2 records", progress[1].Item2);
    }

    private IFileIngestionReader Setup(string content, bool enabled = true)
    {
        _fileManager.OpenStreamFromFile(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(_ => new MemoryStream(Encoding.UTF8.GetBytes(content)));
        return enabled
            ? new RawExportIngestionReader(_fileManager, _timeProvider, _logger)
            : new FileIngestionReader(_fileManager);
    }

    private static async Task<List<string>> ReadAllAsync(IFileIngestionReader reader)
    {
        var records = new List<string>();
        await foreach (var raw in reader.ReadAsync("capture.log", CancellationToken.None))
        {
            records.Add(raw);
        }

        return records;
    }

    private sealed class AdvancingStream(byte[] bytes, int chunkSize, FakeTimeProvider timeProvider) : MemoryStream(bytes)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            timeProvider.Advance(TimeSpan.FromSeconds(5));
            return base.ReadAsync(buffer[..Math.Min(buffer.Length, chunkSize)], cancellationToken);
        }
    }
}
