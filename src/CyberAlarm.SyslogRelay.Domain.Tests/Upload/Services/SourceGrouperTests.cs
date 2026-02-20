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
            .AppendAndSaveItemsAsNdjson(
                Arg.Is<IEnumerable<ParsedEvent>>(events => events.Count() == 2 && events.All(e => e.EventSource.Source == parsedEvent1.EventSource.Source)),
                Arg.Is<string>(path => path.EndsWith(".tmp")),
                cancellationTokenSource.Token);
        await _builder.FileManager
            .Received()
            .AppendAndSaveItemsAsNdjson(
                Arg.Is<IEnumerable<ParsedEvent>>(events => events.Count() == 1 && events.First().EventSource.Source == parsedEvent3.EventSource.Source),
                Arg.Is<string>(path => path.EndsWith(".tmp")),
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
            .When(fm => fm.AppendAndSaveItemsAsNdjson(Arg.Any<IEnumerable<ParsedEvent>>(), Arg.Any<string>(), Arg.Any<CancellationToken>()))
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
            .AppendAndSaveItemsAsNdjson(Arg.Any<IEnumerable<ParsedEvent>>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
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
}
