using CyberAlarm.SyslogRelay.Domain.Tests;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;
using CyberAlarm.SyslogRelay.Tests.Common;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Upload.Services;

public class FileSelectorTests
{
    private const string _inputFolderName = "logs";
    private const string _processingFolderName = "processing";
    private readonly FileSelectorBuilder _builder;

    public FileSelectorTests()
    {
        _builder = new FileSelectorBuilder();
    }

    [Fact]
    public async Task GetsInputFolder()
    {
        var systemUnderTest = _builder.Build();

        await systemUnderTest.SelectFilesAsync(CancellationToken.None);

        _builder.FileManager.Received().GetLogsFolder();
    }

    [Fact]
    public async Task GetsProcessingFolder()
    {
        var systemUnderTest = _builder.Build();

        await systemUnderTest.SelectFilesAsync(CancellationToken.None);

        _builder.FileManager.Received().GetProcessingFolder();
    }

    [Fact]
    public async Task ListsFileInInputFolder()
    {
        _builder.FileManager
            .GetLogsFolder()
            .Returns(_inputFolderName);
        var systemUnderTest = _builder.Build();

        await systemUnderTest.SelectFilesAsync(CancellationToken.None);

        _builder.FileManager
            .Received()
            .ListFilesInDirectory(_inputFolderName);
    }

    [Fact]
    public async Task LogsIntentionToMoveFiles()
    {
        _builder.FileManager
            .GetLogsFolder()
            .Returns(_inputFolderName);
        _builder.FileManager
            .GetProcessingFolder()
            .Returns(_processingFolderName);
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(
            [
                Path.Combine(_inputFolderName, "file1.json"),
                Path.Combine(_inputFolderName, "file2.json"),
                Path.Combine(_inputFolderName, "file3.json")
            ]);
        var systemUnderTest = _builder.Build();

        await systemUnderTest.SelectFilesAsync(CancellationToken.None);

        Assert.Contains(_builder.Logger.ReceivedLogs(),
            log => log.LogLevel == LogLevel.Information
                && log.Message == $"Moving 3 file(s) from {_inputFolderName} to {_processingFolderName}");
    }

    [Fact]
    public async Task MovesFilesToProcessingFolder()
    {
        _builder.FileManager
            .GetLogsFolder()
            .Returns(_inputFolderName);
        _builder.FileManager
            .GetProcessingFolder()
            .Returns(_processingFolderName);
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(
            [
                Path.Combine(_inputFolderName, "file1.json"),
                Path.Combine(_inputFolderName, "file2.json"),
                Path.Combine(_inputFolderName, "file3.json")
            ]);
        var systemUnderTest = _builder.Build();

        await systemUnderTest.SelectFilesAsync(CancellationToken.None);

        _builder.FileManager
            .Received()
            .Move(
                Path.Combine(_inputFolderName, "file1.json"),
                Path.Combine(_processingFolderName, "file1.json")
                );
        _builder.FileManager
            .Received()
            .Move(
                Path.Combine(_inputFolderName, "file2.json"),
                Path.Combine(_processingFolderName, "file2.json")
                );
        _builder.FileManager
            .Received()
            .Move(
                Path.Combine(_inputFolderName, "file3.json"),
                Path.Combine(_processingFolderName, "file3.json")
                );
    }

    [Fact]
    public async Task LogsErrorsAndContinues()
    {
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.json"]);
        _builder.FileManager
            .When(fm => fm.Move(Arg.Any<string>(), Arg.Any<string>()))
            .Throw(new IOException("Simulated file move error"));
        var systemUnderTest = _builder.Build();

        await systemUnderTest.SelectFilesAsync(CancellationToken.None);

        Assert.Contains(_builder.Logger.ReceivedLogs(),
            log => log.LogLevel == LogLevel.Error
                && log.Message == "Error moving file 'file1.json' to processing folder: Simulated file move error");
    }
}
