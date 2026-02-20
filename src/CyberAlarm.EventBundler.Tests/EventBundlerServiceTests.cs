using System.Security.Cryptography;
using CyberAlarm.EventBundler.Tests.Builders;
using CyberAlarm.SyslogRelay.Common.EventBundler.Models;
using CyberAlarm.SyslogRelay.Common.EventBundler.Settings;
using NSubstitute;

namespace CyberAlarm.EventBundler.Tests;

public sealed class EventBundlerServiceTests : IDisposable
{
    private readonly EventBundlerServiceBuilder _builder = new();
    RSA serverKey = RSA.Create(4096);
    RSA syslogRelayKey = RSA.Create(4096);
    string _relayId = "relay-123";
    Platform _platform = new Platform("Test", "1.0", "x64");
    string _buildVersion = "1.0.0";
    MemoryStream _output = new MemoryStream();
    MemoryStream _testData = new MemoryStream();
    MemoryStream _buffer = new MemoryStream();
    byte[] _syslogRelayPrivateKey;
    byte[] _serverPublicKey;
    BundleOptions _options = new BundleOptions();

    EventBundle _sampleEvent;

    public EventBundlerServiceTests()
    {

        _syslogRelayPrivateKey = syslogRelayKey.ExportRSAPrivateKey();
        _serverPublicKey = serverKey.ExportRSAPublicKey();
        _sampleEvent = new EventBundle(
            new Envelope(_buildVersion, new Signature("TestAlgo")),
            new Document(_buildVersion,
                new RelayMetaData(_relayId, _buildVersion, _platform, "TestFingerprint"),
                new Server("ServerFingerprint"),
                new Encryption([0x01, 0x02], "AES", "RSA", "Brotli"),
                DateTime.UtcNow,
                [0x01, 0x02]));
    }

    [Fact]
    public async Task BundleAddsMetaDataToEventBundleCorrectly()
    {
        // Arrange
        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.BundleAsync(
            _testData,
            _output,
            _buffer,
            _relayId,
            _buildVersion,
            _platform,
            _syslogRelayPrivateKey,
            _serverPublicKey,
            _options,
            CancellationToken.None);

        Assert.Equal(_buildVersion, result.Document.Relay.Version);
        Assert.Equal(_relayId, result.Document.Relay.Id);
        Assert.Equal(_platform.Architecture, result.Document.Relay.Platform.Architecture);
        Assert.Equal(_platform.Runtime, result.Document.Relay.Platform.Runtime);
        Assert.Equal(_platform.Os, result.Document.Relay.Platform.Os);
    }

    [Fact]
    public async Task BundleUsesCorrectPrivateKeyToSign()
    {
        // Arrange
        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.BundleAsync(
            _testData,
            _output,
            _buffer,
            _relayId,
            _buildVersion,
            _platform,
            _syslogRelayPrivateKey,
            _serverPublicKey,
            _options,
            CancellationToken.None);

        // Assert
        _builder.DefaultSigner.Received(1).Sign(Arg.Is<byte[]>(_syslogRelayPrivateKey), Arg.Any<Stream>());
        Assert.Equal(_builder.DefaultSigner.AlgorithmName, result.Envelope.Signature.Algorithm);
    }
    [Fact]
    public async Task CorrectCertFingerPrintsAddedToDocument()
    {
        // Arrange
        var unitUnderTest = _builder.Build();
        var knownPrivateKey = Variables.Key4096.ExportRSAPublicKey();
        // Act
        var result = await unitUnderTest.BundleAsync(
            _testData,
            _output,
            _buffer,
            _relayId,
            _buildVersion,
            _platform,
            _syslogRelayPrivateKey,
            knownPrivateKey,
            _options,
            CancellationToken.None);

        // Assert

        Assert.Equal(GetThumbprint(syslogRelayKey), result.Document.Relay.PublicKeyFingerprint);
        Assert.Equal(Variables.HexThumbprint, result.Document.Server.PublicKeyFingerprint);
    }
    [Fact]
    public async Task RequiresKeysToBe4096InSize()
    {
        // Arrange
        var unitUnderTest = _builder.Build();
        var badKey = RSA.Create(2048).ExportRSAPublicKey();

        // Act & Assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(async () =>
            await unitUnderTest.BundleAsync(
                _testData,
                _output,
                _buffer,
                _relayId,
                _buildVersion,
                _platform,
                _syslogRelayPrivateKey,
                badKey,
                _options,
                CancellationToken.None));

        Assert.Equal("serverPublicKey", exception.ParamName);
        Assert.Contains("RSA key must be 4096 bits", exception.Message);
        Assert.Contains("Provided key is 2048 bits", exception.Message);
    }
    [Fact]
    public async Task BundleCallsEventPackerCompressAndEncryptWithCorrectParameters()
    {
        // Arrange
        var unitUnderTest = _builder.Build();

        // Act
        await unitUnderTest.BundleAsync(
            _output,
            _testData,
            _buffer,
            _relayId,
            _buildVersion,
            _platform,
            _syslogRelayPrivateKey,
            _serverPublicKey,
            _options,
            CancellationToken.None);

        // Assert
        await _builder.EventPackerService.Received(1).CompressAndEncrypt(
            Arg.Is<byte[]>(_serverPublicKey),
            Arg.Is<Stream>(_output),
            Arg.Is<Stream>(_testData),
            Arg.Is<Stream>(_buffer),
            Arg.Is<string>(_options.CompressionAlgorithm),
            Arg.Is<string>(_options.SymmetricEncryptionAlgorithm),
            Arg.Is<string>(_options.AsymmetricEncryptionAlgorithm),
            Arg.Any<CancellationToken>());
    }
    [Fact]
    public async Task BundleSetsEncryptedDataInDocumentFromEventPacker()
    {
        // Arrange
        var unitUnderTest = _builder.Build();

        _builder.EventPackerService
            .CompressAndEncrypt(
                Arg.Any<byte[]>(),
                Arg.Any<Stream>(),
                Arg.Any<Stream>(),
                Arg.Any<Stream>(),
                Arg.Any<string>(),
                Arg.Any<string>(),
                Arg.Any<string>(),
                Arg.Any<CancellationToken>())
            .Returns(_sampleEvent.Document.Encryption);

        // Act
        var result = await unitUnderTest.BundleAsync(
            _output,
            _testData,
            _buffer,
            _relayId,
            _buildVersion,
            _platform,
            _syslogRelayPrivateKey,
            _serverPublicKey,
            _options,
            CancellationToken.None);

        // Assert
        Assert.Equal(_sampleEvent.Document.Encryption, result.Document.Encryption);
    }



    private static string GetThumbprint(RSA key)
    {
        var publicKey = key.ExportSubjectPublicKeyInfo();
        var hash = SHA256.HashData(publicKey);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public void Dispose()
    {
        _testData.Dispose();
        _buffer.Dispose();
        _output.Dispose();
    }
}
