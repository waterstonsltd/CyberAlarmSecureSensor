using CyberAlarm.SyslogRelay.Domain.Ingestion;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;
using CyberAlarm.SyslogRelay.Tests.Common;
using Microsoft.Extensions.Logging;
using NSubstitute.ExceptionExtensions;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Ingestion;

public sealed class FileWatcherTests
{
    private readonly FileWatcherBuilder _builder = new();

    [Fact]
    public async Task StartAsync_should_throw_when_ingestAction_is_null()
    {
        // Arrange
        var unitUnderTest = _builder.Build();

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await unitUnderTest.StartAsync(default, CancellationToken.None));
    }

    [Fact]
    public async Task StartAsync_should_stop_periodic_operation_when_drop_path_is_not_set()
    {
        // Arrange
        var options = new RelayOptionsBuilder()
            .WithFileWatcherDropPath(string.Empty)
            .Build();

        var unitUnderTest = _builder
            .WithOptions(options)
            .Build();

        // Act
        await unitUnderTest.StartAsync(
            (syslogEvent, cancellationToken) => Task.CompletedTask,
            CancellationToken.None);

        // Assert
        await _builder.PeriodicOperation.Received(1).StopAsync();
    }

    [Fact]
    public async Task StartAsync_should_stop_periodic_operation_when_drop_path_does_not_exist()
    {
        // Arrange
        _builder.FileManager
            .Exists(Arg.Any<string>())
            .Returns(false);

        var unitUnderTest = _builder.Build();

        // Act
        await unitUnderTest.StartAsync(
            (syslogEvent, cancellationToken) => Task.CompletedTask,
            CancellationToken.None);

        // Assert
        await _builder.PeriodicOperation.Received(1).StopAsync();
    }

    [Fact]
    public async Task StartAsync_should_start_periodic_operation()
    {
        // Arrange
        var unitUnderTest = _builder.Build();

        // Act
        await unitUnderTest.StartAsync(
            (syslogEvent, cancellationToken) => Task.CompletedTask,
            CancellationToken.None);

        // Assert
        _builder.PeriodicOperation.ReceivedWithAnyArgs(1).Start(default, default);
    }

    [Fact]
    public async Task StartAsync_should_iterate_through_all_files_in_drop_path_and_subfolders()
    {
        // Arrange
        var dropPath = "drop";
        var options = new RelayOptionsBuilder()
            .WithFileWatcherDropPath(dropPath)
            .Build();

        var unitUnderTest = _builder
            .WithOptions(options)
            .Build();

        // Act
        await unitUnderTest.StartAsync(
            (syslogEvent, cancellationToken) => Task.CompletedTask,
            CancellationToken.None);

        // Assert
        _builder.FileManager.ReceivedWithAnyArgs(1).ListFileNamesInDirectory(dropPath);
        _builder.FileManager.ReceivedWithAnyArgs(1).ListDirectoryNamesInDirectory(dropPath);
    }

    [Fact]
    public async Task StartAsync_should_rename_ingest_and_delete_files()
    {
        // Arrange
        var dropPath = "drop";
        var file = "x";
        var markedFile = MarkedFile.Create(file).Name;
        var markedFilePath = Path.Combine(dropPath, markedFile);

        var options = new RelayOptionsBuilder()
            .WithFileWatcherDropPath(dropPath)
            .Build();

        _builder.FileManager
            .ListFileNamesInDirectory(dropPath)
            .Returns([file]);

        var unitUnderTest = _builder
            .WithOptions(options)
            .Build();

        // Act
        await unitUnderTest.StartAsync(
            (syslogEvent, cancellationToken) => Task.CompletedTask,
            CancellationToken.None);

        // Assert
        Assert.Contains((LogLevel.Debug, $"Ingesting 1 file(s) from folder '{dropPath}'."), _builder.Logger.ReceivedLogs());
        Assert.Contains((LogLevel.Debug, $"Renaming file '{file}' to '{markedFile}' in folder '{dropPath}'."), _builder.Logger.ReceivedLogs());
        Assert.Contains((LogLevel.Debug, $"Ingesting file '{markedFilePath}' from source 'root'."), _builder.Logger.ReceivedLogs());
        Assert.Contains((LogLevel.Debug, $"Deleting marked file '{markedFile}' from folder '{dropPath}'."), _builder.Logger.ReceivedLogs());
    }

    [Fact]
    public async Task StartAsync_should_skip_file_when_its_retryCount_exceeds_maximum_limit()
    {
        // Arrange
        var dropPath = "drop";
        var file = "~1.x";

        var options = new RelayOptionsBuilder()
            .WithFileWatcherDropPath(dropPath)
            .WithFileWatcherMaximumRetryCount(1)
            .Build();

        _builder.FileManager
            .ListFileNamesInDirectory(dropPath)
            .Returns([file]);

        var unitUnderTest = _builder
            .WithOptions(options)
            .Build();

        // Act
        await unitUnderTest.StartAsync(
            (syslogEvent, cancellationToken) => Task.CompletedTask,
            CancellationToken.None);

        // Assert
        Assert.Contains((LogLevel.Debug, $"Ingesting 1 file(s) from folder '{dropPath}'."), _builder.Logger.ReceivedLogs());
        Assert.Contains((LogLevel.Warning, $"Skipping file '{file}' in folder '{dropPath}' as it exceeds maximum retry count '1'."), _builder.Logger.ReceivedLogs());
    }

    [Fact]
    public async Task StartAsync_should_skip_file_when_it_fails_ingestion()
    {
        // Arrange
        var dropPath = "drop";
        var file = "x";
        var markedFile = MarkedFile.Create(file).Name;
        var markedFilePath = Path.Combine(dropPath, markedFile);

        var options = new RelayOptionsBuilder()
            .WithFileWatcherDropPath(dropPath)
            .Build();

        _builder.FileManager
            .ListFileNamesInDirectory(dropPath)
            .Returns([file]);
        _builder.FileManager
            .OpenStreamFromFile(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Throws<Exception>();

        var unitUnderTest = _builder
            .WithOptions(options)
            .Build();

        // Act
        await unitUnderTest.StartAsync(
            (syslogEvent, cancellationToken) => Task.CompletedTask,
            CancellationToken.None);

        // Assert
        Assert.Contains((LogLevel.Debug, $"Ingesting 1 file(s) from folder '{dropPath}'."), _builder.Logger.ReceivedLogs());
        Assert.Contains((LogLevel.Debug, $"Renaming file '{file}' to '{markedFile}' in folder '{dropPath}'."), _builder.Logger.ReceivedLogs());
        Assert.Contains((LogLevel.Debug, $"Ingesting file '{markedFilePath}' from source 'root'."), _builder.Logger.ReceivedLogs());
        Assert.Contains((LogLevel.Error, $"Error when ingesting file '{markedFilePath}' from source 'root'."), _builder.Logger.ReceivedLogs());
        _builder.FileManager.DidNotReceiveWithAnyArgs().Delete(default);
    }

    [Fact]
    public async Task StopAsync_should_stop_periodic_operation()
    {
        // Arrange
        var unitUnderTest = _builder.Build();

        // Act
        await unitUnderTest.StopAsync();

        // Assert
        await _builder.PeriodicOperation.Received(1).StopAsync();
    }
}
