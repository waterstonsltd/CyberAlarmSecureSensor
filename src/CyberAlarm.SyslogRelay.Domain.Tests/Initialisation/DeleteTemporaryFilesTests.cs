using System;
using System.Collections.Generic;
using System.Text;
using CyberAlarm.SyslogRelay.Domain.Initialisation;
using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Initialisation;

public class DeleteTemporaryFilesTests
{
    [Fact]
    public async Task RunAsync_WithNoFiles_ReturnsOkResult()
    {
        // Arrange
        var sut = new DeleteTemporaryFilesBuilder()
            .WithTemporaryFolder("C:\\Temp")
            .WithFiles()
            .Build();

        // Act
        var result = await sut.RunAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public async Task RunAsync_WithSingleFile_DeletesFile()
    {
        // Arrange
        var fileManager = Substitute.For<IFileManager>();
        var sut = new DeleteTemporaryFilesBuilder()
            .WithFileManager(fileManager)
            .WithTemporaryFolder("C:\\Temp")
            .WithFiles("C:\\Temp\\file1.txt")
            .Build();

        // Act
        await sut.RunAsync(CancellationToken.None);

        // Assert
        fileManager.Received(1).Delete("C:\\Temp\\file1.txt");
    }

    [Fact]
    public async Task RunAsync_WithMultipleFiles_DeletesAllFiles()
    {
        // Arrange
        var fileManager = Substitute.For<IFileManager>();
        var sut = new DeleteTemporaryFilesBuilder()
            .WithFileManager(fileManager)
            .WithTemporaryFolder("C:\\Temp")
            .WithFiles("C:\\Temp\\file1.txt", "C:\\Temp\\file2.txt", "C:\\Temp\\file3.txt")
            .Build();

        // Act
        await sut.RunAsync(CancellationToken.None);

        // Assert
        fileManager.Received(1).Delete("C:\\Temp\\file1.txt");
        fileManager.Received(1).Delete("C:\\Temp\\file2.txt");
        fileManager.Received(1).Delete("C:\\Temp\\file3.txt");
    }

    [Fact]
    public async Task RunAsync_WhenDeleteThrowsException_StillReturnsOkResult()
    {
        // Arrange
        var exception = new IOException("File locked");
        var sut = new DeleteTemporaryFilesBuilder()
            .WithTemporaryFolder("C:\\Temp")
            .WithFiles("C:\\Temp\\file1.txt")
            .WithDeleteException("C:\\Temp\\file1.txt", exception)
            .Build();

        // Act
        var result = await sut.RunAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public async Task RunAsync_WhenSomeDeletesFail_ContinuesWithRemainingFiles()
    {
        // Arrange
        var fileManager = Substitute.For<IFileManager>();
        var exception = new IOException("File locked");
        var sut = new DeleteTemporaryFilesBuilder()
            .WithFileManager(fileManager)
            .WithTemporaryFolder("C:\\Temp")
            .WithFiles("C:\\Temp\\file1.txt", "C:\\Temp\\file2.txt", "C:\\Temp\\file3.txt")
            .WithDeleteException("C:\\Temp\\file2.txt", exception)
            .Build();

        // Act
        await sut.RunAsync(CancellationToken.None);

        // Assert
        fileManager.Received(1).Delete("C:\\Temp\\file1.txt");
        fileManager.Received(1).Delete("C:\\Temp\\file2.txt");
        fileManager.Received(1).Delete("C:\\Temp\\file3.txt");
    }

    [Fact]
    public async Task RunAsync_CallsGetTemporaryFolder()
    {
        // Arrange
        var fileManager = Substitute.For<IFileManager>();
        var sut = new DeleteTemporaryFilesBuilder()
            .WithFileManager(fileManager)
            .WithTemporaryFolder("C:\\Temp")
            .Build();

        // Act
        await sut.RunAsync(CancellationToken.None);

        // Assert
        fileManager.Received(1).GetTemporaryFolder();
    }

    [Fact]
    public async Task RunAsync_CallsListFilesInDirectory()
    {
        // Arrange
        var fileManager = Substitute.For<IFileManager>();
        var sut = new DeleteTemporaryFilesBuilder()
            .WithFileManager(fileManager)
            .WithTemporaryFolder("C:\\Temp")
            .Build();

        // Act
        await sut.RunAsync(CancellationToken.None);

        // Assert
        fileManager.Received(1).ListFilesInDirectory("C:\\Temp");
    }
}
