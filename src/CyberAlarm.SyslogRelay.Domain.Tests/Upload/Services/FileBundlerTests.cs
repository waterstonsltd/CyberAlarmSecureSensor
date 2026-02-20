using CyberAlarm.SyslogRelay.Domain.Tests;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;
using CyberAlarm.SyslogRelay.Common.EventBundler.Models;
using CyberAlarm.SyslogRelay.Common.EventBundler.Settings;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Tests.Common;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using System.Text;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Upload.Services;

public sealed class FileBundlerTests
{
    private readonly FileBundlerBuilder _builder;
    private const string _sourceGroupFolderName = "source-groups";
    private const string _uploadFolderName = "upload";
    private const string _failedFolderName = "failed";

    public FileBundlerTests()
    {
        _builder = new FileBundlerBuilder();
    }

    [Fact]
    public async Task GetsInputFolder()
    {
        var systemUnderTest = _builder.Build();

        await systemUnderTest.BundleFilesAsync(CancellationToken.None);

        _builder.FileManager.Received().GetSourceGroupFolder();
    }

    [Fact]
    public async Task GetsOutputFolder()
    {
        var systemUnderTest = _builder.Build();

        await systemUnderTest.BundleFilesAsync(CancellationToken.None);

        _builder.FileManager.Received().GetUploadFolder();
    }

    [Fact]
    public async Task ListsFileInProcessingFolder()
    {
        _builder.FileManager
            .GetSourceGroupFolder()
            .Returns(_sourceGroupFolderName);
        var systemUnderTest = _builder.Build();

        await systemUnderTest.BundleFilesAsync(CancellationToken.None);

        _builder.FileManager.Received().ListFilesInDirectory(_sourceGroupFolderName);
    }

    [Fact]
    public async Task ReadsEachFile()
    {
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["source1/file1.log", "source2/file2.log", "source3/file3.log"]);
        var systemUnderTest = _builder.Build();

        await systemUnderTest.BundleFilesAsync(CancellationToken.None);

        _builder.FileManager
            .Received()
            .OpenStreamFromFile("source1/file1.log", Arg.Any<CancellationToken>());
        _builder.FileManager
            .Received()
            .OpenStreamFromFile("source2/file2.log", Arg.Any<CancellationToken>());
        _builder.FileManager
            .Received()
            .OpenStreamFromFile("source3/file3.log", Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task PassesFileContentsToBundler()
    {
        var syslogEvent1 = SyslogEvent.FromTcp("test.source.ip.1", "line1");
        var syslogEvent2 = SyslogEvent.FromTcp("test.source.ip.1", "line2");
        var syslogEvent3 = SyslogEvent.FromTcp("test.source.ip.1", "line3");
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["source1/file1.log"]);
        _builder.FileManager
            .DeserialiseFromFileAsync<SyslogEvent[]>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns([syslogEvent1, syslogEvent2, syslogEvent3]);
        var systemUnderTest = _builder.Build();

        await systemUnderTest.BundleFilesAsync(CancellationToken.None);


        _builder.FileManager.Received().OpenStreamFromFile(Arg.Is<string>(s => s == "source1/file1.log"), Arg.Any<CancellationToken>());

    }

    [Fact]
    public async Task PassesPlatformToBundler()
    {
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["source1/file1.log"]);
        _builder.PlatformService
            .GetPlatform()
            .Returns(new Domain.Services.Platform("test os", "test runtime", "test architecture", true));
        var systemUnderTest = _builder.Build();

        await systemUnderTest.BundleFilesAsync(CancellationToken.None);

        await _builder.EventBundler
            .Received()
            .BundleAsync(
                Arg.Any<Stream>(),
                Arg.Any<Stream>(),
                Arg.Any<Stream>(),
                Arg.Any<string>(),
                Arg.Any<string>(),
                Arg.Is<Platform>(platform =>
                    platform.Os == "test os"
                    && platform.Architecture == "test architecture"
                    && platform.Runtime == "test runtime"),
                Arg.Any<byte[]>(),
                Arg.Any<byte[]>(),
                Arg.Any<BundleOptions>(),
                CancellationToken.None);
    }

    [Fact]
    public async Task PassesPublicAndPrivateKeyToBundler()
    {
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["source1/file1.log"]);
        var privateKey = "test private key";
        var publicKey = "test public key";
        var status = new RelayStatusBuilder()
            .WithServerPublicKey(publicKey)
            .Build();
        _builder.RsaKeyProvider
            .GetPrivateKeyDer(Arg.Any<CancellationToken>())
            .Returns(Encoding.UTF8.GetBytes(privateKey));
        _builder.StatusService
            .GetStatusAsync(Arg.Any<CancellationToken>())
            .Returns(status);
        _builder.RsaKeyProvider
            .GetPublicKeyDerBytes(publicKey)
            .Returns(Encoding.UTF8.GetBytes(publicKey));
        var systemUnderTest = _builder.Build();

        await systemUnderTest.BundleFilesAsync(CancellationToken.None);

        await _builder.EventBundler
            .Received()
            .BundleAsync(
                Arg.Any<Stream>(),
                Arg.Any<Stream>(),
                Arg.Any<Stream>(),
                Arg.Any<string>(),
                Arg.Any<string>(),
                Arg.Any<Platform>(),
                Arg.Is<byte[]>(array => array.SequenceEqual(Encoding.UTF8.GetBytes(privateKey))),
                Arg.Is<byte[]>(array => array.SequenceEqual(Encoding.UTF8.GetBytes(publicKey))),
                Arg.Any<BundleOptions>(),
                CancellationToken.None);
    }

    [Fact]
    public async Task PassesBuildVersionToBundler()
    {
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["source1/file1.log"]);
        var relayOptions = new RelayOptionsBuilder()
            .WithBuildVersion("test build version")
            .Build();
        var systemUnderTest = _builder
            .WithRelayOptions(relayOptions)
            .Build();

        await systemUnderTest.BundleFilesAsync(CancellationToken.None);

        await _builder.EventBundler
            .Received()
            .BundleAsync(
                Arg.Any<Stream>(),
                Arg.Any<Stream>(),
                Arg.Any<Stream>(),
                Arg.Any<string>(),
                "test build version",
                Arg.Any<Platform>(),
                Arg.Any<byte[]>(),
                Arg.Any<byte[]>(),
                Arg.Any<BundleOptions>(),
                CancellationToken.None);
    }

    [Fact]
    public async Task PassesRelayIdToBundler()
    {
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["source1/file1.log"]);
        var relayOptions = new RelayOptionsBuilder()
            .WithRegistrationToken("1.userName.token")
            .Build();
        var systemUnderTest = _builder
            .WithRelayOptions(relayOptions)
            .Build();

        await systemUnderTest.BundleFilesAsync(CancellationToken.None);

        await _builder.EventBundler
            .Received()
            .BundleAsync(
                Arg.Any<Stream>(),
                Arg.Any<Stream>(),
                Arg.Any<Stream>(),
                "1.userName",
                Arg.Any<string>(),
                Arg.Any<Platform>(),
                Arg.Any<byte[]>(),
                Arg.Any<byte[]>(),
                Arg.Any<BundleOptions>(),
                CancellationToken.None);
    }

    [Fact]
    public async Task DeletesProcessedFiles()
    {
        _builder.FileManager
            .GetSourceGroupFolder()
            .Returns("source1");
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["source1/file1.log"]);
        var systemUnderTest = _builder.Build();

        await systemUnderTest.BundleFilesAsync(CancellationToken.None);

        _builder.FileManager
            .Received()
            .Delete("source1/file1.log");
    }

    [Fact]
    public async Task PassesCancellationTokenOnwards()
    {
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["source1/file1.log"]);
        var systemUnderTest = _builder.Build();

        var cancellationTokenSource = new CancellationTokenSource();
        var cancellationToken = cancellationTokenSource.Token;
        await systemUnderTest.BundleFilesAsync(cancellationToken);

        _builder.FileManager.Received().OpenStreamFromFile(Arg.Any<string>(), cancellationToken);
        _builder.FileManager.Received().OpenWriteStreamForFile(Arg.Any<string>(), cancellationToken);
    }

    [Fact]
    public async Task RespectsCancellationToken()
    {
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["source1/file1.log"]);
        var systemUnderTest = _builder.Build();
        var cancellationTokenSource = new CancellationTokenSource();
        cancellationTokenSource.Cancel();

        var activityTask = systemUnderTest.BundleFilesAsync(cancellationTokenSource.Token);

        await Assert.ThrowsAsync<OperationCanceledException>(() => activityTask);
    }

    [Fact]
    public async Task FailingToBundleLogsAnError()
    {
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["source1/file1.log"]);
        _builder.EventBundler
            .When(eventBundler => eventBundler.BundleAsync(
                Arg.Any<Stream>(),
                Arg.Any<Stream>(),
                Arg.Any<Stream>(),
                Arg.Any<string>(),
                Arg.Any<string>(),
                Arg.Any<Platform>(),
                Arg.Any<byte[]>(),
                Arg.Any<byte[]>(),
                Arg.Any<BundleOptions>(),
                CancellationToken.None))
            .Do(call => throw new CryptographicException("Bundling failed"));
        var systemUnderTest = _builder.Build();

        var activityTask = systemUnderTest.BundleFilesAsync(CancellationToken.None);

        var logs = _builder.Logger.ReceivedLogs();
        Assert.Contains(logs,
            log => log.LogLevel == LogLevel.Error
                && log.Message == "Failed to bundle file 'file1.log'");
    }

    [Fact]
    public async Task MovedFailedFilesToFailedFolder()
    {
        _builder.FileManager
            .GetFailedFolder()
            .Returns(_failedFolderName);
        _builder.FileManager
            .ListFilesInDirectory(Arg.Any<string>())
            .Returns(["source1/file1.log"]);
        _builder.EventBundler
            .When(eventBundler => eventBundler.BundleAsync(
                Arg.Any<Stream>(),
                Arg.Any<Stream>(),
                Arg.Any<Stream>(),
                Arg.Any<string>(),
                Arg.Any<string>(),
                Arg.Any<Platform>(),
                Arg.Any<byte[]>(),
                Arg.Any<byte[]>(),
                Arg.Any<BundleOptions>(),
                CancellationToken.None))
            .Do(call => throw new CryptographicException("Bundling failed"));
        var systemUnderTest = _builder.Build();

        var activityTask = systemUnderTest.BundleFilesAsync(CancellationToken.None);

        _builder.FileManager
            .Received()
            .Move("source1/file1.log", Path.Combine(_failedFolderName, "file1.log"));
    }
}
