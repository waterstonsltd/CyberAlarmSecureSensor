using CyberAlarm.SyslogRelay.Common.EventBundler.Models;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;
using CyberAlarm.SyslogRelay.Tests.Common;
using Microsoft.Extensions.Logging;
using NSubstitute.ExceptionExtensions;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Upload.Services;

public class SourceGrouperTests
{
    private const string _processingFolderName = "processing";
    private const string _sourceGroupFolderName = "output";
    private const string _failedFolderName = "failed";
    private readonly SourceGrouperBuilder _builder = new();

    [Fact]
    public async Task LogsCompletion()
    {
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.log"]);
        _builder.FileManager
            .DeserialiseFromNdjson<ParsedEvent>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns([new ParsedEventBuilder().Build()]);
        var systemUnderTest = _builder.Build();

        await systemUnderTest.GroupLogsBySourceAsync(CancellationToken.None);

        Assert.Contains(_builder.Logger.ReceivedLogs(),
            log => log.LogLevel == LogLevel.Information && log.Message!.StartsWith("Grouping complete:"));
    }

    [Fact]
    public async Task GetsProcessingFolder()
    {
        var systemUnderTest = _builder.Build();

        await systemUnderTest.GroupLogsBySourceAsync(CancellationToken.None);

        _builder.FileManager
            .Received()
            .GetProcessingFolder();
    }

    [Fact]
    public async Task GetsSourceGroupFolder()
    {
        var systemUnderTest = _builder.Build();

        await systemUnderTest.GroupLogsBySourceAsync(CancellationToken.None);

        _builder.FileManager
            .Received()
            .GetSourceGroupFolder();
    }

    [Fact]
    public async Task GetsFailedFolder()
    {
        var systemUnderTest = _builder.Build();

        await systemUnderTest.GroupLogsBySourceAsync(CancellationToken.None);

        _builder.FileManager
            .Received()
            .GetFailedFolder();
    }

    [Fact]
    public async Task ListsFilesFromProcessingFolder()
    {
        _builder.FileManager
            .GetProcessingFolder()
            .Returns(_processingFolderName);
        var systemUnderTest = _builder.Build();

        await systemUnderTest.GroupLogsBySourceAsync(CancellationToken.None);

        _builder.FileManager
            .Received()
            .ListFilesInDirectory(_processingFolderName);
    }

    [Fact]
    public async Task LogsTotalFileCount()
    {
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.log", "file2.log", "file3.log"]);
        var systemUnderTest = _builder.Build();

        await systemUnderTest.GroupLogsBySourceAsync(CancellationToken.None);

        Assert.Contains(_builder.Logger.ReceivedLogs(),
            log => log.LogLevel == LogLevel.Information && log.Message == "Found 3 files to group");
    }

    [Fact]
    public async Task DeserialisesEachFile()
    {
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.log", "file2.log", "file3.log"]);
        var systemUnderTest = _builder.Build();
        var cancellationTokenSource = new CancellationTokenSource();

        await systemUnderTest.GroupLogsBySourceAsync(cancellationTokenSource.Token);

        await _builder.FileManager
            .Received()
            .DeserialiseFromNdjson<ParsedEvent>("file1.log", cancellationTokenSource.Token);
        await _builder.FileManager
            .Received()
            .DeserialiseFromNdjson<ParsedEvent>("file2.log", cancellationTokenSource.Token);
        await _builder.FileManager
            .Received()
            .DeserialiseFromNdjson<ParsedEvent>("file3.log", cancellationTokenSource.Token);
    }

    [Fact]
    public async Task GroupsEventsBySource()
    {
        var parsedEvent1 = new ParsedEventBuilder().WithSource("s1").Build();
        var parsedEvent2 = new ParsedEventBuilder().WithSource("s1").Build();
        var parsedEvent3 = new ParsedEventBuilder().WithSource("s2").Build();
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.log"]);
        _builder.FileManager
            .DeserialiseFromNdjson<ParsedEvent>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns([parsedEvent1, parsedEvent2, parsedEvent3]);
        _builder.FileManager
            .GetSourceGroupFolder()
            .Returns(_sourceGroupFolderName);
        var systemUnderTest = _builder.Build();
        var cancellationTokenSource = new CancellationTokenSource();

        await systemUnderTest.GroupLogsBySourceAsync(cancellationTokenSource.Token);

        await _builder.FileManager
            .Received()
            .SerialiseToFileAsync(
                Arg.Is<Dictionary<string, EventsMetaData>>(metaData =>
                    metaData.Count == 2 &&
                    metaData.Values.Any(x => x.Source == parsedEvent1.EventSource.Source) &&
                    metaData.Values.Any(x => x.Source == parsedEvent3.EventSource.Source)),
                Arg.Any<string>(),
                cancellationTokenSource.Token);

        _builder.FileManager
          .Received()
          .Move(Arg.Any<string>(),
              Arg.Is<string>(path => path.Contains(parsedEvent1.EventSource.Source) && path.EndsWith(".ndjson")));

        _builder.FileManager
          .Received()
          .Move(Arg.Any<string>(),
              Arg.Is<string>(path => path.Contains(parsedEvent3.EventSource.Source) && path.EndsWith(".ndjson")));
    }

    [Fact]
    public async Task FinalizesTemporaryFileToLogFile()
    {
        var parsedEvent = new ParsedEventBuilder().Build();
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.log"]);
        _builder.FileManager
            .DeserialiseFromNdjson<ParsedEvent>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns([parsedEvent]);
        _builder.FileManager
            .GetSourceGroupFolder()
            .Returns(_sourceGroupFolderName);
        var systemUnderTest = _builder.Build();

        await systemUnderTest.GroupLogsBySourceAsync(CancellationToken.None);

        _builder.FileManager
            .Received()
            .Move(
                Arg.Is<string>(path => path.EndsWith(".tmp")),
                Arg.Is<string>(path => path.EndsWith(".ndjson")));
    }

    [Fact]
    public async Task DeletesSourceFileAfterFinalization()
    {
        var parsedEvent = new ParsedEventBuilder().Build();
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.log"]);
        _builder.FileManager
            .DeserialiseFromNdjson<ParsedEvent>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns([parsedEvent]);
        var systemUnderTest = _builder.Build();

        await systemUnderTest.GroupLogsBySourceAsync(CancellationToken.None);

        _builder.FileManager
            .Received()
            .Delete("file1.log");
    }

    [Fact]
    public async Task DeletesMultipleSourceFilesContributingToSameTempFile()
    {
        var parsedEvent1 = new ParsedEventBuilder().WithSource("x").Build();
        var parsedEvent2 = new ParsedEventBuilder().WithSource("x").Build();
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.log", "file2.log"]);
        _builder.FileManager
            .DeserialiseFromNdjson<ParsedEvent>("file1.log", Arg.Any<CancellationToken>())
            .Returns([parsedEvent1]);
        _builder.FileManager
            .DeserialiseFromNdjson<ParsedEvent>("file2.log", Arg.Any<CancellationToken>())
            .Returns([parsedEvent2]);
        var systemUnderTest = _builder.Build();

        await systemUnderTest.GroupLogsBySourceAsync(CancellationToken.None);

        _builder.FileManager
            .Received()
            .Delete("file1.log");
        _builder.FileManager
            .Received()
            .Delete("file2.log");
    }

    [Fact]
    public async Task MovesFailedFileToFailedFolder()
    {
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.log"]);
        _builder.FileManager
            .DeserialiseFromNdjson<ParsedEvent>("file1.log", Arg.Any<CancellationToken>())
            .ThrowsAsync(new IOException("Test error"));
        _builder.FileManager
            .GetFailedFolder()
            .Returns(_failedFolderName);
        var systemUnderTest = _builder.Build();

        await systemUnderTest.GroupLogsBySourceAsync(CancellationToken.None);

        _builder.FileManager
            .Received()
            .Move("file1.log", Arg.Is<string>(path => path.StartsWith(_failedFolderName) && path.EndsWith("file1.log")));
    }

    [Fact]
    public async Task LogsErrorProcessingFile()
    {
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.log"]);
        _builder.FileManager
            .DeserialiseFromNdjson<ParsedEvent>("file1.log", Arg.Any<CancellationToken>())
            .ThrowsAsync(new IOException("Test error message"));
        var systemUnderTest = _builder.Build();

        await systemUnderTest.GroupLogsBySourceAsync(CancellationToken.None);

        Assert.Contains(_builder.Logger.ReceivedLogs(),
            log => log.LogLevel == LogLevel.Error && log.Message!.Contains("Error processing file file1.log"));
    }

    [Fact]
    public async Task LogsErrorWritingSourceGroup()
    {
        var parsedEvent = new ParsedEventBuilder().Build();
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.log"]);
        _builder.FileManager
            .DeserialiseFromNdjson<ParsedEvent>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns([parsedEvent]);
        _builder.FileManager
            .When(fm => fm.AppendAndSaveItemsAsNdjson(Arg.Any<IEnumerable<BundleEvent>>(), Arg.Any<string>(), Arg.Any<CancellationToken>()))
            .Throws(new IOException("Test error message"));
        var systemUnderTest = _builder.Build();

        await systemUnderTest.GroupLogsBySourceAsync(CancellationToken.None);

        Assert.Contains(_builder.Logger.ReceivedLogs(),
            log => log.LogLevel == LogLevel.Error && log.Message!.Contains("Error processing file file1.log"));
    }

    [Fact]
    public async Task ContinuesProcessingAfterFileError()
    {
        var parsedEvent = new ParsedEventBuilder().Build();

        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.log", "file2.log"]);
        _builder.FileManager
            .DeserialiseFromNdjson<ParsedEvent>("file1.log", Arg.Any<CancellationToken>())
            .ThrowsAsync(new IOException("Test error"));
        _builder.FileManager
            .DeserialiseFromNdjson<ParsedEvent>("file2.log", Arg.Any<CancellationToken>())
            .Returns([parsedEvent]);
        var systemUnderTest = _builder.Build();

        await systemUnderTest.GroupLogsBySourceAsync(CancellationToken.None);

        await _builder.FileManager
            .Received()
            .DeserialiseFromNdjson<ParsedEvent>("file2.log", Arg.Any<CancellationToken>());
        await _builder.FileManager
            .Received()
            .AppendAndSaveItemsAsNdjson(Arg.Any<IEnumerable<BundleEvent>>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task LogsFailedCountInCompletion()
    {
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.log", "file2.log"]);
        _builder.FileManager
            .DeserialiseFromNdjson<ParsedEvent>("file1.log", Arg.Any<CancellationToken>())
            .ThrowsAsync(new IOException("Test error"));
        _builder.FileManager
            .DeserialiseFromNdjson<ParsedEvent>("file2.log", Arg.Any<CancellationToken>())
            .Returns([new ParsedEventBuilder().Build()]);
        var systemUnderTest = _builder.Build();

        await systemUnderTest.GroupLogsBySourceAsync(CancellationToken.None);

        Assert.Contains(_builder.Logger.ReceivedLogs(),
            log => log.LogLevel == LogLevel.Information && log.Message!.Contains("1 files grouped successfully") && log.Message.Contains("1 failed"));
    }

    [Fact]
    public async Task RespectsCancellationTokenDuringFileProcessing()
    {
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.log"]);
        var systemUnderTest = _builder.Build();
        var cancellationTokenSource = new CancellationTokenSource();
        cancellationTokenSource.Cancel();

        var act = async () => await systemUnderTest.GroupLogsBySourceAsync(cancellationTokenSource.Token);

        await Assert.ThrowsAsync<OperationCanceledException>(act);
    }

    [Fact]
    public async Task HandlesNullDeserialisationResult()
    {
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.log"]);
        _builder.FileManager
            .DeserialiseFromNdjson<ParsedEvent>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns((ParsedEvent[]?)null);
        var systemUnderTest = _builder.Build();

        await systemUnderTest.GroupLogsBySourceAsync(CancellationToken.None);

        await _builder.FileManager
            .DidNotReceive()
            .AppendAndSaveItemsAsNdjson(Arg.Any<IEnumerable<ParsedEvent>>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task UploadsUnmatchedEventsWhenRawDataIsAvailable()
    {
        _builder.WithUploadRawLogs(true);
        var parsedEvent = new ParsedEventBuilder()
            .WithValidationStatus(ValidationStatus.UnableToPatternMatch)
            .WithRawData("raw message")
            .Build();
        IEnumerable<BundleEvent>? capturedEvents = null;

        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.log"]);
        _builder.FileManager
            .DeserialiseFromNdjson<ParsedEvent>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns([parsedEvent]);
        _builder.FileManager
            .When(fm => fm.AppendAndSaveItemsAsNdjson(Arg.Any<IEnumerable<BundleEvent>>(), Arg.Any<string>(), Arg.Any<CancellationToken>()))
            .Do(callInfo => capturedEvents = callInfo.Arg<IEnumerable<BundleEvent>>().ToArray());
        var systemUnderTest = _builder.Build();

        await systemUnderTest.GroupLogsBySourceAsync(CancellationToken.None);

        var bundleEvent = Assert.Single(capturedEvents!);
        Assert.Equal("raw message", bundleEvent.RawData);
        Assert.Null(bundleEvent.PatternName);
        Assert.Null(bundleEvent.ParseResult);
    }

    [Fact]
    public async Task UploadsUnparsedEventsWhenRawDataIsAvailable()
    {
        _builder.WithUploadRawLogs(true);
        var parseResult = new ParseResultBuilder().Build();
        var parsedEvent = new ParsedEventBuilder()
            .WithValidationStatus(ValidationStatus.UnableToParse)
            .WithRawData("raw message")
            .WithPatternName("cisco-asa")
            .WithParseResult(parseResult)
            .Build();
        IEnumerable<BundleEvent>? capturedEvents = null;

        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.log"]);
        _builder.FileManager
            .DeserialiseFromNdjson<ParsedEvent>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns([parsedEvent]);
        _builder.FileManager
            .When(fm => fm.AppendAndSaveItemsAsNdjson(Arg.Any<IEnumerable<BundleEvent>>(), Arg.Any<string>(), Arg.Any<CancellationToken>()))
            .Do(callInfo => capturedEvents = callInfo.Arg<IEnumerable<BundleEvent>>().ToArray());
        var systemUnderTest = _builder.Build();

        await systemUnderTest.GroupLogsBySourceAsync(CancellationToken.None);

        var bundleEvent = Assert.Single(capturedEvents!);
        Assert.Equal("raw message", bundleEvent.RawData);
        Assert.Equal("cisco-asa", bundleEvent.PatternName);
        Assert.Equal(parseResult, bundleEvent.ParseResult);
    }

    [Fact]
    public async Task DoesNotUploadUnmatchedEventsWhenRawDataIsMissing()
    {
        var parsedEvent = new ParsedEventBuilder()
            .WithValidationStatus(ValidationStatus.UnableToPatternMatch)
            .WithRawData(null)
            .Build();

        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.log"]);
        _builder.FileManager
            .DeserialiseFromNdjson<ParsedEvent>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns([parsedEvent]);
        var systemUnderTest = _builder.Build();

        await systemUnderTest.GroupLogsBySourceAsync(CancellationToken.None);

        await _builder.FileManager
            .DidNotReceive()
            .AppendAndSaveItemsAsNdjson(
                Arg.Is<IEnumerable<BundleEvent>>(events => events.Any()),
                Arg.Any<string>(),
                Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task DoesNotUploadEventsWhenParsedDataAndRawDataAreMissing()
    {
        var parsedEvent = new ParsedEventBuilder()
            .WithPatternName("Cisco ASA")
            .WithParseResult(null)
            .WithRawData(null)
            .Build();

        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.log"]);
        _builder.FileManager
            .DeserialiseFromNdjson<ParsedEvent>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns([parsedEvent]);
        var systemUnderTest = _builder.Build();

        await systemUnderTest.GroupLogsBySourceAsync(CancellationToken.None);

        await _builder.FileManager
            .DidNotReceive()
            .AppendAndSaveItemsAsNdjson(
                Arg.Is<IEnumerable<BundleEvent>>(events => events.Any()),
                Arg.Any<string>(),
                Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task UploadsParsedEventsWhenRawDataIsMissing()
    {
        var parseResult = new ParseResultBuilder().Build();
        var parsedEvent = new ParsedEventBuilder()
            .WithPatternName("Cisco ASA")
            .WithParseResult(parseResult)
            .WithRawData(null)
            .Build();
        IEnumerable<BundleEvent>? capturedEvents = null;

        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.log"]);
        _builder.FileManager
            .DeserialiseFromNdjson<ParsedEvent>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns([parsedEvent]);
        _builder.FileManager
            .When(fm => fm.AppendAndSaveItemsAsNdjson(Arg.Any<IEnumerable<BundleEvent>>(), Arg.Any<string>(), Arg.Any<CancellationToken>()))
            .Do(callInfo => capturedEvents = callInfo.Arg<IEnumerable<BundleEvent>>().ToArray());
        var systemUnderTest = _builder.Build();

        await systemUnderTest.GroupLogsBySourceAsync(CancellationToken.None);

        var bundleEvent = Assert.Single(capturedEvents!);
        Assert.Null(bundleEvent.RawData);
        Assert.Equal("Cisco ASA", bundleEvent.PatternName);
        Assert.Equal(parseResult, bundleEvent.ParseResult);
    }

    [Fact]
    public async Task UploadsAllEventsWhenRawDataIsAvailable()
    {
        _builder.WithUploadRawLogs(true);
        var parsedEvent = new ParsedEventBuilder()
            .WithPatternName("Cisco ASA")
            .WithParseResult(new ParseResultBuilder().Build())
            .WithRawData("parsed raw message")
            .Build();
        var unparsedEvent = new ParsedEventBuilder()
            .WithValidationStatus(ValidationStatus.UnableToParse)
            .WithPatternName("Cisco ASA")
            .WithRawData("unparsed raw message")
            .Build();
        var unmatchedEvent = new ParsedEventBuilder()
            .WithValidationStatus(ValidationStatus.UnableToPatternMatch)
            .WithRawData("unmatched raw message")
            .Build();
        IEnumerable<BundleEvent>? capturedEvents = null;

        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.log"]);
        _builder.FileManager
            .DeserialiseFromNdjson<ParsedEvent>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns([parsedEvent, unparsedEvent, unmatchedEvent]);
        _builder.FileManager
            .When(fm => fm.AppendAndSaveItemsAsNdjson(Arg.Any<IEnumerable<BundleEvent>>(), Arg.Any<string>(), Arg.Any<CancellationToken>()))
            .Do(callInfo => capturedEvents = callInfo.Arg<IEnumerable<BundleEvent>>().ToArray());
        var systemUnderTest = _builder.Build();

        await systemUnderTest.GroupLogsBySourceAsync(CancellationToken.None);

        var bundleEvents = Assert.IsType<IEnumerable<BundleEvent>>(capturedEvents, exactMatch: false);

        Assert.Equal(3, bundleEvents.Count());
        Assert.Contains(bundleEvents, evt => evt.RawData == "parsed raw message" && evt.ParseResult is not null);
        Assert.Contains(bundleEvents, evt => evt.RawData == "unparsed raw message" && evt.PatternName == "Cisco ASA" && evt.ParseResult is null);
        Assert.Contains(bundleEvents, evt => evt.RawData == "unmatched raw message" && evt.PatternName is null && evt.ParseResult is null);
    }

    [Fact]
    public async Task DoesNotUploadIgnoredEvents()
    {
        var ignoredEvent = new ParsedEventBuilder()
            .WithValidationStatus(ValidationStatus.Ignored)
            .WithRawData("type=\"siem\" msg=<Event>...")
            .Build();

        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.log"]);
        _builder.FileManager
            .DeserialiseFromNdjson<ParsedEvent>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns([ignoredEvent]);
        var systemUnderTest = _builder.Build();

        await systemUnderTest.GroupLogsBySourceAsync(CancellationToken.None);

        await _builder.FileManager
            .DidNotReceive()
            .AppendAndSaveItemsAsNdjson(
                Arg.Is<IEnumerable<BundleEvent>>(events => events.Any()),
                Arg.Any<string>(),
                Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task UploadsIgnoredEventsWhenUploadRawLogsIsEnabled()
    {
        _builder.WithUploadRawLogs(true);
        var ignoredEvent = new ParsedEventBuilder()
            .WithValidationStatus(ValidationStatus.Ignored)
            .WithRawData("type=\"siem\" msg=<Event>...")
            .Build();
        IEnumerable<BundleEvent>? capturedEvents = null;

        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.log"]);
        _builder.FileManager
            .DeserialiseFromNdjson<ParsedEvent>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns([ignoredEvent]);
        _builder.FileManager
            .When(fm => fm.AppendAndSaveItemsAsNdjson(Arg.Any<IEnumerable<BundleEvent>>(), Arg.Any<string>(), Arg.Any<CancellationToken>()))
            .Do(callInfo => capturedEvents = callInfo.Arg<IEnumerable<BundleEvent>>().ToArray());
        var systemUnderTest = _builder.Build();

        await systemUnderTest.GroupLogsBySourceAsync(CancellationToken.None);

        var bundleEvent = Assert.Single(capturedEvents!);
        Assert.Equal("type=\"siem\" msg=<Event>...", bundleEvent.RawData);
    }

    [Fact]
    public async Task CountsIgnoredEventsInMetaData()
    {
        var ignoredEvent = new ParsedEventBuilder()
            .WithValidationStatus(ValidationStatus.Ignored)
            .WithSource("fortigate-1")
            .Build();
        Dictionary<string, EventsMetaData>? capturedMetaData = null;

        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.log"]);
        _builder.FileManager
            .DeserialiseFromNdjson<ParsedEvent>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns([ignoredEvent]);
        _builder.FileManager
            .GetSourceGroupFolder()
            .Returns(_sourceGroupFolderName);
        _builder.FileManager
            .When(fm => fm.SerialiseToFileAsync(Arg.Any<Dictionary<string, EventsMetaData>>(), Arg.Any<string>(), Arg.Any<CancellationToken>()))
            .Do(callInfo => capturedMetaData = callInfo.Arg<Dictionary<string, EventsMetaData>>());
        var systemUnderTest = _builder.Build();

        await systemUnderTest.GroupLogsBySourceAsync(CancellationToken.None);

        Assert.NotNull(capturedMetaData);
        var meta = Assert.Single(capturedMetaData.Values);
        Assert.Equal(1, meta.IgnoredEvents);
        Assert.Equal(1, meta.TotalEvents);
    }

    [Fact]
    public async Task LogsWarningWhenFailedToDeleteSourceFile()
    {
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.log"]);
        _builder.FileManager
            .DeserialiseFromNdjson<ParsedEvent>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns([new ParsedEventBuilder().Build()]);
        _builder.FileManager
            .When(fm => fm.Delete("file1.log"))
            .Throw(new IOException("File locked"));
        var systemUnderTest = _builder.Build();

        await systemUnderTest.GroupLogsBySourceAsync(CancellationToken.None);

        Assert.Contains(_builder.Logger.ReceivedLogs(),
            log => log.LogLevel == LogLevel.Warning && log.Message!.Contains("Failed to delete source file file1.log"));
    }

    [Fact]
    public async Task DoesNotIncludeRawDataOrValidationStatusForSuccessEventWhenUploadRawLogsIsFalse()
    {
        var parseResult = new ParseResultBuilder().Build();
        var parsedEvent = new ParsedEventBuilder()
            .WithValidationStatus(ValidationStatus.Success)
            .WithParseResult(parseResult)
            .WithRawData("raw message")
            .Build();
        IEnumerable<BundleEvent>? capturedEvents = null;

        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.log"]);
        _builder.FileManager
            .DeserialiseFromNdjson<ParsedEvent>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns([parsedEvent]);
        _builder.FileManager
            .When(fm => fm.AppendAndSaveItemsAsNdjson(Arg.Any<IEnumerable<BundleEvent>>(), Arg.Any<string>(), Arg.Any<CancellationToken>()))
            .Do(callInfo => capturedEvents = callInfo.Arg<IEnumerable<BundleEvent>>().ToArray());
        var systemUnderTest = _builder.Build();

        await systemUnderTest.GroupLogsBySourceAsync(CancellationToken.None);

        var bundleEvent = Assert.Single(capturedEvents!);
        Assert.Null(bundleEvent.RawData);
        Assert.Null(bundleEvent.ValidationStatus);
        Assert.Equal(parseResult, bundleEvent.ParseResult);
    }

    [Fact]
    public async Task DoesNotUploadNonSuccessEventsWhenUploadRawLogsIsFalse()
    {
        var parsedEvent = new ParsedEventBuilder()
            .WithValidationStatus(ValidationStatus.LocalOnlyEvent)
            .WithRawData("raw message")
            .Build();

        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.log"]);
        _builder.FileManager
            .DeserialiseFromNdjson<ParsedEvent>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns([parsedEvent]);
        var systemUnderTest = _builder.Build();

        await systemUnderTest.GroupLogsBySourceAsync(CancellationToken.None);

        await _builder.FileManager
            .DidNotReceive()
            .AppendAndSaveItemsAsNdjson(
                Arg.Is<IEnumerable<BundleEvent>>(events => events.Any()),
                Arg.Any<string>(),
                Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task IncludesRawDataAndValidationStatusForSuccessEventWhenUploadRawLogsIsTrue()
    {
        _builder.WithUploadRawLogs(true);
        var parseResult = new ParseResultBuilder().Build();
        var parsedEvent = new ParsedEventBuilder()
            .WithValidationStatus(ValidationStatus.Success)
            .WithParseResult(parseResult)
            .WithRawData("raw message")
            .Build();
        IEnumerable<BundleEvent>? capturedEvents = null;

        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.log"]);
        _builder.FileManager
            .DeserialiseFromNdjson<ParsedEvent>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns([parsedEvent]);
        _builder.FileManager
            .When(fm => fm.AppendAndSaveItemsAsNdjson(Arg.Any<IEnumerable<BundleEvent>>(), Arg.Any<string>(), Arg.Any<CancellationToken>()))
            .Do(callInfo => capturedEvents = callInfo.Arg<IEnumerable<BundleEvent>>().ToArray());
        var systemUnderTest = _builder.Build();

        await systemUnderTest.GroupLogsBySourceAsync(CancellationToken.None);

        var bundleEvent = Assert.Single(capturedEvents!);
        Assert.Equal("raw message", bundleEvent.RawData);
        Assert.Equal(ValidationStatus.Success, bundleEvent.ValidationStatus);
        Assert.Equal(parseResult, bundleEvent.ParseResult);
    }

    [Fact]
    public async Task IncludesValidationStatusForNonSuccessEventWhenUploadRawLogsIsTrue()
    {
        _builder.WithUploadRawLogs(true);
        var parsedEvent = new ParsedEventBuilder()
            .WithValidationStatus(ValidationStatus.LocalOnlyEvent)
            .WithRawData("raw message")
            .Build();
        IEnumerable<BundleEvent>? capturedEvents = null;

        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.log"]);
        _builder.FileManager
            .DeserialiseFromNdjson<ParsedEvent>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns([parsedEvent]);
        _builder.FileManager
            .When(fm => fm.AppendAndSaveItemsAsNdjson(Arg.Any<IEnumerable<BundleEvent>>(), Arg.Any<string>(), Arg.Any<CancellationToken>()))
            .Do(callInfo => capturedEvents = callInfo.Arg<IEnumerable<BundleEvent>>().ToArray());
        var systemUnderTest = _builder.Build();

        await systemUnderTest.GroupLogsBySourceAsync(CancellationToken.None);

        var bundleEvent = Assert.Single(capturedEvents!);
        Assert.Equal("raw message", bundleEvent.RawData);
        Assert.Equal(ValidationStatus.LocalOnlyEvent, bundleEvent.ValidationStatus);
    }

    [Fact]
    public async Task PreservesExistingMetaDataEntriesFromPreviousRun()
    {
        var parsedEvent = new ParsedEventBuilder().WithSource("new-source").Build();
        var existingEntry = new EventsMetaData("udp", "old-survivor", 5, 0, 0, 0);
        Dictionary<string, EventsMetaData>? capturedMetaData = null;

        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.log"]);
        _builder.FileManager
            .DeserialiseFromNdjson<ParsedEvent>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns([parsedEvent]);
        _builder.FileManager
            .GetSourceGroupFolder()
            .Returns(_sourceGroupFolderName);
        _builder.FileManager
            .DeserialiseFromFileAsync<Dictionary<string, EventsMetaData>>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new Dictionary<string, EventsMetaData> { ["old-survivor.ndjson"] = existingEntry });
        _builder.FileManager
            .When(fm => fm.SerialiseToFileAsync(Arg.Any<Dictionary<string, EventsMetaData>>(), Arg.Any<string>(), Arg.Any<CancellationToken>()))
            .Do(callInfo => capturedMetaData = callInfo.Arg<Dictionary<string, EventsMetaData>>());
        var systemUnderTest = _builder.Build();

        await systemUnderTest.GroupLogsBySourceAsync(CancellationToken.None);

        Assert.NotNull(capturedMetaData);
        Assert.True(capturedMetaData.ContainsKey("old-survivor.ndjson"), "Existing crash-survivor entry should be preserved in merged metadata");
        Assert.Contains(capturedMetaData.Values, v => v.Source == parsedEvent.EventSource.Source);
    }

    [Fact]
    public async Task CountsOutboundEventsInMetaData()
    {
        var outboundEvent = new ParsedEventBuilder()
            .WithValidationStatus(ValidationStatus.OutboundEvent)
            .WithSource("fortigate-1")
            .Build();
        Dictionary<string, EventsMetaData>? capturedMetaData = null;

        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.log"]);
        _builder.FileManager
            .DeserialiseFromNdjson<ParsedEvent>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns([outboundEvent]);
        _builder.FileManager
            .GetSourceGroupFolder()
            .Returns(_sourceGroupFolderName);
        _builder.FileManager
            .When(fm => fm.SerialiseToFileAsync(Arg.Any<Dictionary<string, EventsMetaData>>(), Arg.Any<string>(), Arg.Any<CancellationToken>()))
            .Do(callInfo => capturedMetaData = callInfo.Arg<Dictionary<string, EventsMetaData>>());
        var systemUnderTest = _builder.Build();

        await systemUnderTest.GroupLogsBySourceAsync(CancellationToken.None);

        Assert.NotNull(capturedMetaData);
        var meta = Assert.Single(capturedMetaData.Values);
        Assert.Equal(1, meta.OutboundEvents);
        Assert.Equal(1, meta.TotalEvents);
    }

    [Fact]
    public async Task DoesNotUploadOutboundEventsWhenUploadRawLogsIsFalse()
    {
        var outboundEvent = new ParsedEventBuilder()
            .WithValidationStatus(ValidationStatus.OutboundEvent)
            .WithRawData("outbound traffic raw message")
            .Build();

        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.log"]);
        _builder.FileManager
            .DeserialiseFromNdjson<ParsedEvent>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns([outboundEvent]);
        var systemUnderTest = _builder.Build();

        await systemUnderTest.GroupLogsBySourceAsync(CancellationToken.None);

        await _builder.FileManager
            .DidNotReceive()
            .AppendAndSaveItemsAsNdjson(
                Arg.Is<IEnumerable<BundleEvent>>(events => events.Any()),
                Arg.Any<string>(),
                Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task UploadsOutboundEventsWhenUploadRawLogsIsEnabled()
    {
        _builder.WithUploadRawLogs(true);
        var outboundEvent = new ParsedEventBuilder()
            .WithValidationStatus(ValidationStatus.OutboundEvent)
            .WithRawData("outbound traffic raw message")
            .Build();
        IEnumerable<BundleEvent>? capturedEvents = null;

        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.log"]);
        _builder.FileManager
            .DeserialiseFromNdjson<ParsedEvent>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns([outboundEvent]);
        _builder.FileManager
            .When(fm => fm.AppendAndSaveItemsAsNdjson(Arg.Any<IEnumerable<BundleEvent>>(), Arg.Any<string>(), Arg.Any<CancellationToken>()))
            .Do(callInfo => capturedEvents = callInfo.Arg<IEnumerable<BundleEvent>>().ToArray());
        var systemUnderTest = _builder.Build();

        await systemUnderTest.GroupLogsBySourceAsync(CancellationToken.None);

        var bundleEvent = Assert.Single(capturedEvents!);
        Assert.Equal("outbound traffic raw message", bundleEvent.RawData);
        Assert.Equal(ValidationStatus.OutboundEvent, bundleEvent.ValidationStatus);
    }
}
