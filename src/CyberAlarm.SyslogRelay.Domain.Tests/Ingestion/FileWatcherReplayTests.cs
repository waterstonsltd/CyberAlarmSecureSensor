using System.Text;
using System.Text.Json;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.HealthCheck;
using CyberAlarm.SyslogRelay.Domain.Ingestion;
using CyberAlarm.SyslogRelay.Domain.Parsing;
using CyberAlarm.SyslogRelay.Domain.Parsing.PfSense;
using CyberAlarm.SyslogRelay.Domain.PatternMatching;
using CyberAlarm.SyslogRelay.Domain.Pipeline;
using CyberAlarm.SyslogRelay.Domain.Pipeline.Stages;
using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;
using CyberAlarm.SyslogRelay.Tests.Common;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using static CyberAlarm.SyslogRelay.Domain.Tests.Ingestion.RawExportTestData;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Ingestion;

public sealed class FileWatcherReplayTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Ingestion_uses_current_time_and_root_source_and_deletes_successful_files(bool replay)
    {
        var builder = Setup(Example, replay);
        var captured = new List<SyslogEvent>();
        var before = DateTime.UtcNow;
        using var watcher = builder.Build();
        await watcher.StartAsync((item, _) =>
        {
            captured.Add(item);
            return Task.CompletedTask;
        }, CancellationToken.None);
        var result = Assert.Single(captured);
        Assert.Equal(replay ? Expected : Example, result.RawData);
        Assert.Equal(new EventSource(IngestionMethod.File, FileWatcher.RootSource), result.EventSource);
        Assert.InRange(result.Timestamp, before, DateTime.UtcNow);
        builder.FileManager.Received(1).Delete(Path.Combine("drop", MarkedFile.Create("capture.log").Name));
        Assert.Contains((LogLevel.Information, $"File import raw export replay: {replay}."), builder.Logger.ReceivedLogs());
    }

    [Fact]
    public async Task Local_exports_preserve_raw_exactly_once_and_use_the_drop_subfolder_source()
    {
        const string raw = "<134>message \"quoted\" C:\\logs literal \\u003C and & caf\u00e9";
        var builder = Setup(Export(raw), subfolder: "firewall-a");
        var captured = new List<SyslogEvent>();
        using var watcher = builder.Build();
        await watcher.StartAsync((item, _) =>
        {
            captured.Add(item);
            return Task.CompletedTask;
        }, CancellationToken.None);
        var result = Assert.Single(captured);
        Assert.Equal(raw, result.RawData);
        Assert.Equal(new EventSource(IngestionMethod.File, "firewall-a"), result.EventSource);
        var persisted = new ParsedEvent(result.Timestamp, result.EventSource, result.RawData,
            "Unknown", null, ValidationStatus.UnableToParse);
        using var json = JsonDocument.Parse(JsonSerializer.Serialize(persisted));
        Assert.Equal(raw, json.RootElement.GetProperty("RawData").GetString());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Invalid_exports_are_retained_without_partial_ingestion(bool invalidFirstLine)
    {
        const string invalid = """{"Timestamp":"old","PatternName":"test","ParseResult":null,"RawData":null}""";
        var builder = Setup(invalidFirstLine ? invalid : Example + "\n" + invalid);
        var emitted = 0;
        using var watcher = builder.Build();
        await watcher.StartAsync((_, _) =>
        {
            emitted++;
            return Task.CompletedTask;
        }, CancellationToken.None);
        Assert.Equal(0, emitted);
        builder.FileManager.DidNotReceiveWithAnyArgs().Delete(default!);
        Assert.Contains(builder.Logger.ReceivedLogs(), log => log.Item1 == LogLevel.Error);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Cancellation_during_ingestion_keeps_the_marked_file(bool replay)
    {
        var builder = Setup(Example + "\n" + Example, replay);
        using var cancellation = new CancellationTokenSource();
        var periodic = Substitute.For<IPeriodicOperation>();
        var options = Options.Create(new RelayOptions
        {
            FileWatcherEnabled = true, FileWatcherReplayRawExports = replay, FileWatcherDropPath = "drop", FileWatcherMaximumRetryCount = 5,
        });
        IFileIngestionReader reader = replay
            ? new RawExportIngestionReader(builder.FileManager, TimeProvider.System, NullLogger<RawExportIngestionReader>.Instance)
            : new FileIngestionReader(builder.FileManager);
        using var watcher = new FileWatcher(builder.FileManager, reader, periodic, builder.HealthCheckService, options, builder.Logger);
        PeriodicOperationSettings? settings = null;
        periodic.When(item => item.Start(Arg.Any<PeriodicOperationSettings>(), Arg.Any<CancellationToken>()))
            .Do(call => settings = call.Arg<PeriodicOperationSettings>());
        var emitted = 0;
        await watcher.StartAsync((_, _) =>
        {
            emitted++;
            cancellation.Cancel();
            return Task.CompletedTask;
        }, CancellationToken.None);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => settings!.Operation(cancellation.Token));
        Assert.Equal(1, emitted);
        builder.FileManager.DidNotReceiveWithAnyArgs().Delete(default!);
    }

    [Fact]
    public async Task Downstream_failure_disposes_the_reader_and_keeps_the_file()
    {
        var builder = Setup(Example + "\n" + Example);
        var stream = new MemoryStream(Encoding.UTF8.GetBytes(Example + "\n" + Example));
        builder.FileManager.OpenStreamFromFile(Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(stream);
        using var watcher = builder.Build();
        await watcher.StartAsync((_, _) => throw new InvalidOperationException("Pipeline failed."), CancellationToken.None);
        Assert.False(stream.CanRead);
        builder.FileManager.DidNotReceiveWithAnyArgs().Delete(default!);
        Assert.Contains(builder.Logger.ReceivedLogs(), log => log.Item1 == LogLevel.Error);
    }

    [Fact]
    public async Task Replay_reparses_and_revalidates_instead_of_reusing_exported_results()
    {
        const string raw = "filterlog: 1,,,1000000103,em0,match,pass,in,4,0,,64,0,0,none,6,tcp,60,10.0.0.10,8.8.8.8,50000,443,0,S,100,0";
        var builder = Setup(Export(raw));
        var options = new PipelineOptions();
        var services = new PipelineStageServices(Substitute.For<IApplicationManager>(), Substitute.For<IHealthCheckService>(),
            Options.Create(options), new PipelineMetrics(new TestMeterFactory()));
        var completed = new TaskCompletionSource<ValidationStageOutput>(TaskCreationOptions.RunContinuationsAsynchronously);
        var sink = Substitute.For<IPipelineStage<ValidationStageOutput>>();
        sink.EnqueueAsync(Arg.Any<ValidationStageOutput>(), Arg.Any<CancellationToken>()).Returns(call =>
        {
            completed.TrySetResult(call.Arg<ValidationStageOutput>());
            return Task.CompletedTask;
        });
        var validation = new ValidationStageBuilder().Build();
        validation.NextStage = sink;
        var parsing = new ParsingStage(services, NullLogger<ParsingStage>.Instance) { NextStage = validation };
        var matcher = Substitute.For<IPatternMatchingService>();
        matcher.MatchPatternAsync(raw, Arg.Any<CancellationToken>())
            .Returns(new PatternMatchResult("Current pfSense", new PfSenseParser()));
        var matching = new PatternMatchingStage(matcher, services, NullLogger<PatternMatchingStage>.Instance) { NextStage = parsing };
        await validation.StartAsync(CancellationToken.None);
        await parsing.StartAsync(CancellationToken.None);
        await matching.StartAsync(CancellationToken.None);
        using var watcher = builder.Build();
        try
        {
            await watcher.StartAsync(matching.EnqueueAsync, CancellationToken.None);
            var result = await completed.Task.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.Equal("10.0.0.10", result.ParseResult!.SourceIp);
            Assert.Equal(ValidationStatus.OutboundEvent, result.ValidationResult.ValidationStatus);
            Assert.Equal("Current pfSense", result.PatternMatchResult!.PatternName);
            await matcher.Received(1).MatchPatternAsync(raw, Arg.Any<CancellationToken>());
        }
        finally
        {
            await matching.StopAsync(CancellationToken.None);
            await parsing.StopAsync(CancellationToken.None);
            await validation.StopAsync(CancellationToken.None);
        }
    }

    private static FileWatcherBuilder Setup(string content, bool enabled = true, string? subfolder = null)
    {
        var builder = new FileWatcherBuilder().WithOptions(new RelayOptionsBuilder()
            .WithFileWatcherEnabled(true).WithFileWatcherReplayRawExports(enabled).WithFileWatcherDropPath("drop").Build());
        var folder = subfolder is null ? "drop" : Path.Combine("drop", subfolder);
        builder.FileManager.ListFileNamesInDirectory(folder).Returns(["capture.log"]);
        if (subfolder is not null)
        {
            builder.FileManager.ListDirectoryNamesInDirectory("drop").Returns([subfolder]);
        }

        builder.FileManager.OpenStreamFromFile(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(_ => new MemoryStream(Encoding.UTF8.GetBytes(content)));
        return builder;
    }
}
