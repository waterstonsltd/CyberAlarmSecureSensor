using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.HealthCheck;
using CyberAlarm.SyslogRelay.Domain.Pipeline;
using CyberAlarm.SyslogRelay.Domain.Pipeline.Stages;
using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Tests.Common;
using FluentResults;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Pipeline;

public sealed class ParsingStageTests
{
    [Fact]
    public async Task Should_log_parse_failure_summary_without_raw_event_data()
    {
        // Arrange
        const string rawData = "secret-payload";
        var input = new PatternMatchingStageOutput(
            SyslogEvent.FromFile("root", rawData),
            new PatternMatchResult("Fortigate", new FailingParser()));

        var logger = CreateLogger();
        var outputs = new List<ParsingStageOutput>();
        var unitUnderTest = CreateStage(outputs, logger);

        // Act
        await unitUnderTest.StartAsync(CancellationToken.None);
        await unitUnderTest.EnqueueAsync(input, CancellationToken.None);
        await unitUnderTest.StopAsync(CancellationToken.None);

        // Assert
        Assert.Single(outputs);

        var message = Assert.Single(logger.ReceivedLogs()
            .Where(log => log.Message?.Contains("Failed to parse", StringComparison.Ordinal) == true)
            .Select(log => log.Message));

        Assert.Equal("Failed to parse 1 event(s) with pattern 'Fortigate' and parser 'FailingParser'.", message);
        Assert.DoesNotContain(rawData, message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Should_rate_limit_parse_failure_logs_within_interval()
    {
        // Arrange — time is frozen so all rapid failures fall within the 1-minute window.
        var timeProvider = new FakeTimeProvider();
        var logger = CreateLogger();
        var outputs = new List<ParsingStageOutput>();
        var unitUnderTest = CreateStage(outputs, logger, timeProvider);

        // Act
        await unitUnderTest.StartAsync(CancellationToken.None);

        for (var count = 0; count < 100; count++)
        {
            await unitUnderTest.EnqueueAsync(
                new PatternMatchingStageOutput(
                    SyslogEvent.FromFile("root", $"raw-{count}"),
                    new PatternMatchResult("Fortigate", new FailingParser())),
                CancellationToken.None);
        }

        await unitUnderTest.StopAsync(CancellationToken.None);

        // Assert — only the first failure should be logged; the rest are within the interval.
        var parseFailureLogs = logger.ReceivedLogs()
            .Where(log => log.Message?.Contains("Failed to parse", StringComparison.Ordinal) == true)
            .Select(log => log.Message)
            .ToList();

        Assert.Single(parseFailureLogs);
        Assert.Contains("Failed to parse 1 event(s) with pattern 'Fortigate' and parser 'FailingParser'.", parseFailureLogs);
    }

    [Fact]
    public async Task Should_log_parse_failure_again_after_interval_elapses()
    {
        // Arrange
        var timeProvider = new FakeTimeProvider();
        var logger = CreateLogger();
        var outputs = new List<ParsingStageOutput>();
        var signal = new SignallingStage<ParsingStageOutput>(outputs);
        var unitUnderTest = CreateStageWithNextStage(signal, logger, timeProvider);

        var failingInput = new PatternMatchingStageOutput(
            SyslogEvent.FromFile("root", "raw"),
            new PatternMatchResult("Fortigate", new FailingParser()));

        // Act — enqueue first, wait for it to be processed, then advance time, then enqueue second.
        await unitUnderTest.StartAsync(CancellationToken.None);

        var waitForFirst = signal.WaitForNextAsync();
        await unitUnderTest.EnqueueAsync(failingInput, CancellationToken.None);
        await waitForFirst;

        timeProvider.Advance(TimeSpan.FromHours(2));

        await unitUnderTest.EnqueueAsync(failingInput, CancellationToken.None);
        await unitUnderTest.StopAsync(CancellationToken.None);

        // Assert — both failures should be logged because time elapsed between them.
        var parseFailureLogs = logger.ReceivedLogs()
            .Where(log => log.Message?.Contains("Failed to parse", StringComparison.Ordinal) == true)
            .Select(log => log.Message)
            .ToList();

        Assert.Equal(2, parseFailureLogs.Count);
        Assert.Contains("Failed to parse 1 event(s) with pattern 'Fortigate' and parser 'FailingParser'.", parseFailureLogs);
        Assert.Contains("Failed to parse 2 event(s) with pattern 'Fortigate' and parser 'FailingParser'.", parseFailureLogs);
    }

    [Fact]
    public async Task Should_rate_limit_no_pattern_match_logs_within_interval()
    {
        // Arrange — time is frozen so all rapid misses fall within the 1-minute window.
        var timeProvider = new FakeTimeProvider();
        var logger = CreateLogger();
        var outputs = new List<ParsingStageOutput>();
        var unitUnderTest = CreateStage(outputs, logger, timeProvider);

        // Act
        await unitUnderTest.StartAsync(CancellationToken.None);

        for (var count = 0; count < 100; count++)
        {
            await unitUnderTest.EnqueueAsync(
                new PatternMatchingStageOutput(SyslogEvent.FromFile("root", $"raw-{count}"), null),
                CancellationToken.None);
        }

        await unitUnderTest.StopAsync(CancellationToken.None);

        // Assert — only the first miss should be logged.
        var noPatternMatchLogs = logger.ReceivedLogs()
            .Where(log => log.Message?.Contains("Skipped parsing", StringComparison.Ordinal) == true)
            .Select(log => log.Message)
            .ToList();

        Assert.Single(noPatternMatchLogs);
        Assert.Contains("Skipped parsing for 1 event(s) with no matching pattern.", noPatternMatchLogs);
    }

    [Fact]
    public async Task Should_log_no_pattern_match_again_after_interval_elapses()
    {
        // Arrange
        var timeProvider = new FakeTimeProvider();
        var logger = CreateLogger();
        var outputs = new List<ParsingStageOutput>();
        var signal = new SignallingStage<ParsingStageOutput>(outputs);
        var unitUnderTest = CreateStageWithNextStage(signal, logger, timeProvider);

        var noMatchInput = new PatternMatchingStageOutput(SyslogEvent.FromFile("root", "raw"), null);

        // Act — wait for first to be processed before advancing time.
        await unitUnderTest.StartAsync(CancellationToken.None);

        var waitForFirst = signal.WaitForNextAsync();
        await unitUnderTest.EnqueueAsync(noMatchInput, CancellationToken.None);
        await waitForFirst;

        timeProvider.Advance(TimeSpan.FromHours(2));

        await unitUnderTest.EnqueueAsync(noMatchInput, CancellationToken.None);
        await unitUnderTest.StopAsync(CancellationToken.None);

        // Assert
        var noPatternMatchLogs = logger.ReceivedLogs()
            .Where(log => log.Message?.Contains("Skipped parsing", StringComparison.Ordinal) == true)
            .Select(log => log.Message)
            .ToList();

        Assert.Equal(2, noPatternMatchLogs.Count);
        Assert.Contains("Skipped parsing for 1 event(s) with no matching pattern.", noPatternMatchLogs);
        Assert.Contains("Skipped parsing for 2 event(s) with no matching pattern.", noPatternMatchLogs);
    }

    private static ParsingStage CreateStage(
        List<ParsingStageOutput> outputs,
        ILogger<ParsingStage> logger,
        TimeProvider? timeProvider = null)
    {
        return CreateStageWithNextStage(new TestStage<ParsingStageOutput>(outputs), logger, timeProvider);
    }

    private static ParsingStage CreateStageWithNextStage(
        IPipelineStage<ParsingStageOutput> nextStage,
        ILogger<ParsingStage> logger,
        TimeProvider? timeProvider = null)
    {
        var applicationManager = Substitute.For<IApplicationManager>();
        var healthCheckService = Substitute.For<IHealthCheckService>();
        var healthToken = Substitute.For<IHealthToken>();

        healthToken.HealthyAsync(Arg.Any<CancellationToken>()).Returns(Task.CompletedTask);
        healthToken.UnhealthyAsync(Arg.Any<CancellationToken>()).Returns(Task.CompletedTask);
        healthToken.UnregisterAsync(Arg.Any<CancellationToken>()).Returns(Task.CompletedTask);
        healthCheckService.GetHealthToken(Arg.Any<string>()).Returns(healthToken);

        return new ParsingStage(
            new PipelineStageServices(applicationManager, healthCheckService, Options.Create(new PipelineOptions())),
            logger,
            timeProvider)
        {
            NextStage = nextStage,
        };
    }

    private static ILogger<ParsingStage> CreateLogger()
    {
        var logger = Substitute.For<ILogger<ParsingStage>>();
        logger.IsEnabled(Arg.Any<LogLevel>()).Returns(true);
        return logger;
    }

    private sealed class FailingParser : IParser
    {
        public Result Initialise(object? config) => Result.Ok();

        public Result<ParseResult> Parse(string log) => Result.Fail<ParseResult>("Failed");
    }

    /// <summary>
    /// A downstream stage that signals a <see cref="Task"/> each time it receives
    /// a message, enabling tests to wait for a specific item to be processed before
    /// advancing a <see cref="FakeTimeProvider"/>.
    /// </summary>
    private sealed class SignallingStage<TInput>(List<TInput> results) : IPipelineStage<TInput>
    {
        private TaskCompletionSource _tcs = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public IPipelineStage? NextStage => null;

        public Task WaitForNextAsync()
        {
            _tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            return _tcs.Task;
        }

        public Task EnqueueAsync(TInput input, CancellationToken cancellationToken)
        {
            results.Add(input);
            _tcs.TrySetResult();
            return Task.CompletedTask;
        }

        public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}