using CyberAlarm.SyslogRelay.Domain.State;
using CyberAlarm.SyslogRelay.Domain.Tests;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;
using CyberAlarm.SyslogRelay.Tests.Common;
using Microsoft.Extensions.Logging;
using NSubstitute.ExceptionExtensions;
using Renci.SshNet.Common;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Upload.Services;

public sealed class SecureUploaderTests
{
    private readonly SecureUploaderBuilder _builder;
    private const string _uploadFolderName = "upload";

    public SecureUploaderTests()
    {
        _builder = new SecureUploaderBuilder();
    }

    [Fact]
    public async Task GetsInputFolder()
    {
        var systemUnderTest = _builder.Build();

        await systemUnderTest.UploadFilesAsync(CancellationToken.None);

        _builder.FileManager.Received().GetUploadFolder();
    }

    [Fact]
    public async Task ListsFilesInInputFolder()
    {
        _builder.FileManager
            .GetUploadFolder()
            .Returns(_uploadFolderName);
        var systemUnderTest = _builder.Build();

        await systemUnderTest.UploadFilesAsync(CancellationToken.None);

        _builder.FileManager
            .Received()
            .ListFilesInDirectory(_uploadFolderName);
    }

    [Theory]
    [InlineData(new string[] { }, 0)]
    [InlineData(new string[] { "one file" }, 1)]
    [InlineData(new string[] { "one file", "two files" }, 1)]
    public async Task CreatesSecureFtpClientIfThereAreFilesToUpload(string[] files, int expectedCreationCount)
    {
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(files);
        _builder.RsaKeyProvider
            .GetPrivateKeyPem(Arg.Any<CancellationToken>())
            .Returns("test private key");
        var systemUnderTest = _builder
            .WithStorageAccounts(new Dictionary<string, string>
            {
                ["bucket1"] = "ftp.test.server1",
                ["bucket2"] = "ftp.test.server2",
                ["bucket3"] = "ftp.test.server3"
            })
            .WithOptions(new RelayOptions
            {
                RegistrationToken = "bucket1.testUserName.token"
            })
            .Build();

        await systemUnderTest.UploadFilesAsync(CancellationToken.None);

        _builder.SecureFtpClientFactory
            .Received(expectedCreationCount)
            .Create("ftp.test.server1.blob.core.windows.net", "ftp.test.server1.testUserName", "test private key");
    }

    [Fact]
    public async Task LogsIfNoFilesToUpload()
    {
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns([]);
        var systemUnderTest = _builder.Build();

        await systemUnderTest.UploadFilesAsync(CancellationToken.None);

        var logs = _builder.Logger.ReceivedLogs();
        Assert.Contains(logs, log => log.LogLevel == LogLevel.Information && log.Message == "No files to upload");
    }

    [Theory]
    [InlineData(new string[] { }, 0)]
    [InlineData(new string[] { "one file" }, 1)]
    [InlineData(new string[] { "one file", "two files" }, 1)]
    public async Task ConnectsToFtpClientOnceIfThereAreFilesToUpload(string[] files, int expectedConnectCount)
    {
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(files);
        var systemUnderTest = _builder.Build();

        await systemUnderTest.UploadFilesAsync(CancellationToken.None);

        _builder.SecureFtpClient
            .Received(expectedConnectCount)
            .Connect();
    }

    [Fact]
    public async Task ReadsEachFile()
    {
        _builder.FileManager
            .GetUploadFolder()
            .Returns(_uploadFolderName);
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.calr"]);
        var systemUnderTest = _builder.Build();
        var cancellationTokenSource = new CancellationTokenSource();

        await systemUnderTest.UploadFilesAsync(cancellationTokenSource.Token);

        _builder.FileManager
            .Received()
            .OpenStreamFromFile("file1.calr", cancellationTokenSource.Token);
    }

    [Fact]
    public async Task UploadsEachFile()
    {
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.calr"]);
        var mockFile = new MemoryStream();
        _builder.FileManager
            .OpenStreamFromFile(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(mockFile);
        var cancellationTokenSource = new CancellationTokenSource();
        var systemUnderTest = _builder.Build();

        await systemUnderTest.UploadFilesAsync(cancellationTokenSource.Token);

        await _builder.SecureFtpClient
            .Received()
            .UploadFileAsync(mockFile, "file1.calr", cancellationTokenSource.Token);
    }

    [Fact]
    public async Task DisposesFileStream()
    {
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.calr"]);
        var mockFileStream = new MockFileStream();
        _builder.FileManager
            .OpenStreamFromFile(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(mockFileStream);
        var systemUnderTest = _builder.Build();

        await systemUnderTest.UploadFilesAsync(CancellationToken.None);

        Assert.True(mockFileStream.IsDisposed);
    }

    [Theory]
    [InlineData(typeof(SshException))]
    [InlineData(typeof(SshConnectionException))]
    public async Task RetriesIfTheUploadFails(Type exceptionType)
    {
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.calr"]);
        _builder.SecureFtpClient
            .When(client => client.UploadFileAsync(Arg.Any<Stream>(), Arg.Any<string>(), Arg.Any<CancellationToken>()))
            .Do(Callback.First(call => throw (Exception)Activator.CreateInstance(exceptionType)!));

        var systemUnderTest = _builder.Build();

        await systemUnderTest.UploadFilesAsync(CancellationToken.None);

        await _builder.SecureFtpClient
            .Received(2)
            .UploadFileAsync(Arg.Any<Stream>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Theory]
    [InlineData(new string[] { }, 0)]
    [InlineData(new string[] { "one file" }, 1)]
    [InlineData(new string[] { "one file", "two files" }, 1)]
    public async Task DisconnectsFromFtpClientOnceIfThereAreFilesToUpload(string[] files, int expectedDisconnectCount)
    {
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(files);
        var systemUnderTest = _builder.Build();

        await systemUnderTest.UploadFilesAsync(CancellationToken.None);

        _builder.SecureFtpClient
            .Received(expectedDisconnectCount)
            .Disconnect();
    }

    [Fact]
    public async Task DoesNotAttemptToDisconnectIfAllUploadsFailedAndDisconnected()
    {
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.calr"]);
        _builder.SecureFtpClient
            .When(client => client.UploadFileAsync(Arg.Any<Stream>(), Arg.Any<string>(), Arg.Any<CancellationToken>()))
            .Do(call =>
            {
                _builder.IsClientConnected = false;
                throw new SshException("Test exception with disconnect");
            });
        var systemUnderTest = _builder.Build();

        await systemUnderTest.UploadFilesAsync(CancellationToken.None);

        _builder.SecureFtpClient
            .Received(0)
            .Disconnect();
    }

    [Theory]
    [InlineData(typeof(SshAuthenticationException))]
    [InlineData(typeof(SshConnectionException))]
    public async Task BlocksUploadInStateAndStopsApplicationIfUnableToAuthenticateOrConnect(Type exceptionType)
    {
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.calr"]);
        _builder.SecureFtpClient
            .UploadFileAsync(Arg.Any<Stream>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .ThrowsAsync((Exception)Activator.CreateInstance(exceptionType)!);

        var systemUnderTest = _builder.Build();

        await systemUnderTest.UploadFilesAsync(CancellationToken.None);

        await _builder.StateService
            .Received(1)
            .UpdateStateAsync(Arg.Any<Func<RelayState, RelayState>>(), Arg.Any<CancellationToken>());

        _builder.ApplicationManager.Received(1).StopApplication();
    }

    [Fact]
    public async Task DisposesFtpClient()
    {
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.calr"]);
        var systemUnderTest = _builder.Build();

        await systemUnderTest.UploadFilesAsync(CancellationToken.None);

        _builder.SecureFtpClient
            .Received()
            .Dispose();
    }

    [Fact]
    public async Task DeletesFilesOnceUploaded()
    {
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.calr"]);
        var systemUnderTest = _builder.Build();

        await systemUnderTest.UploadFilesAsync(CancellationToken.None);

        _builder.FileManager
            .Received()
            .Delete("file1.calr");
    }

    [Fact]
    public async Task LogsErrorsUploading()
    {
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["source1/file1.calr"]);
        _builder.SecureFtpClient
            .When(client => client.UploadFileAsync(Arg.Any<Stream>(), Arg.Any<string>(), Arg.Any<CancellationToken>()))
            .Do(_ => throw new SshException("Error uploading file"));
        var systemUnderTest = _builder.Build();

        await systemUnderTest.UploadFilesAsync(CancellationToken.None);

        var logs = _builder.Logger.ReceivedLogs();
        Assert.Contains(logs,
            log => log.LogLevel == LogLevel.Error && log.Message == $"Error uploading source1/file1.calr");
    }

    [Fact]
    public async Task RespectsCancellationToken()
    {
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["file1.calr"]);
        var systemUnderTest = _builder.Build();
        var cancellationTokenSource = new CancellationTokenSource();
        cancellationTokenSource.Cancel();

        var activityTask = systemUnderTest.UploadFilesAsync(cancellationTokenSource.Token);

        await Assert.ThrowsAsync<OperationCanceledException>(() => activityTask);
    }
}
