using System.Security.Cryptography;
using CyberAlarm.EventBundler.Plugins.Compressors;
using CyberAlarm.EventBundler.Plugins.Encryptors;
using CyberAlarm.EventBundler.Services;
using NSubstitute;

namespace CyberAlarm.EventBundler.Tests;

public sealed class EventPackerServiceTests : IDisposable
{
    private readonly byte[] _serverPublicKey;
    private readonly Stream _outputStream = new MemoryStream();
    private readonly Stream _bufferStream = new MemoryStream();

    private readonly string _compressionAlgorithm = "Brotli";
    private readonly string _symmetricEncryptionAlgorithm = "AES";
    private readonly string _asymmetricEncryptionAlgorithm = "RSA";

    public EventPackerServiceTests()
    {
        var key = RSA.Create(4096);
        _serverPublicKey = key.ExportRSAPublicKey();
    }

    [Fact]
    public async Task CompressAndEncryptWithValidDataReturnsEncryptionModel()
    {
        // Arrange
        var service = new EventPackerServiceBuilder()
            .Build();

        var testData = new MemoryStream();

        // Act
        var result = await service.CompressAndEncrypt(_serverPublicKey, _outputStream, testData, _bufferStream, _compressionAlgorithm, _symmetricEncryptionAlgorithm, _asymmetricEncryptionAlgorithm, CancellationToken.None);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(_asymmetricEncryptionAlgorithm, result.KeyEncryptionAlgorithm);
        Assert.Equal(_symmetricEncryptionAlgorithm, result.DataEncryptionAlgorithm);
        Assert.Equal(_compressionAlgorithm, result.CompressionAlgorithm);
    }

    [Fact]
    public async Task CompressAndEncryptWithNullCompressionAlgorithmThrowsArgumentException()
    {
        // Arrange
        var service = new EventPackerServiceBuilder()
            .Build();

        var testData = new MemoryStream();

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            service.CompressAndEncrypt(_serverPublicKey, _outputStream, testData, _bufferStream, null!, _symmetricEncryptionAlgorithm, _asymmetricEncryptionAlgorithm, CancellationToken.None));
    }

    [Fact]
    public async Task CompressAndEncryptWithEmptySymmetricAlgorithmThrowsArgumentException()
    {
        // Arrange
        var service = new EventPackerServiceBuilder()
            .Build();

        var testData = new MemoryStream();

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(() =>
            service.CompressAndEncrypt(_serverPublicKey, _outputStream, testData, _bufferStream, _compressionAlgorithm, string.Empty, _asymmetricEncryptionAlgorithm, CancellationToken.None));
    }

    [Fact]
    public async Task CompressAndEncryptWithEmptyAsymmetricAlgorithmThrowsArgumentException()
    {
        // Arrange
        var service = new EventPackerServiceBuilder()
            .Build();

        var testData = new MemoryStream();

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(() =>
            service.CompressAndEncrypt(_serverPublicKey, _outputStream, testData, _bufferStream, _compressionAlgorithm, _symmetricEncryptionAlgorithm, string.Empty, CancellationToken.None));
    }

    [Fact]
    public void ConstructorWithNullCompressorFactoryThrowsArgumentNullException()
    {
        // Act & Assert
        EventPackerServiceBuilder eventPackerServiceBuilder = new EventPackerServiceBuilder();
        Assert.Throws<ArgumentNullException>(() =>
            new EventPackerService(null!, eventPackerServiceBuilder.AsymmetricEncryptorFactory, eventPackerServiceBuilder.SymmetricEncryptorFactory));
    }

    [Fact]
    public void ConstructorWithNullAsymmetricEncryptorFactoryThrowsArgumentNullException()
    {
        // Act & Assert
        EventPackerServiceBuilder eventPackerServiceBuilder = new EventPackerServiceBuilder();
        Assert.Throws<ArgumentNullException>(() =>
            new EventPackerService(eventPackerServiceBuilder.CompressorFactory, null!, eventPackerServiceBuilder.SymmetricEncryptorFactory));
    }

    [Fact]
    public void ConstructorWithNullSymmetricEncryptorFactoryThrowsArgumentNullException()
    {
        // Act & Assert
        EventPackerServiceBuilder eventPackerServiceBuilder = new EventPackerServiceBuilder();
        Assert.Throws<ArgumentNullException>(() =>
            new EventPackerService(eventPackerServiceBuilder.CompressorFactory, eventPackerServiceBuilder.AsymmetricEncryptorFactory, null!));
    }

    [Fact]
    public async Task CompressAndEncryptCallsPluginFactoriesWithCorrectAlgorithms()
    {
        // Arrange
        EventPackerServiceBuilder eventPackerServiceBuilder = new EventPackerServiceBuilder();

        var service = eventPackerServiceBuilder
            .Build();

        var testData = new MemoryStream();

        // Act
        await service.CompressAndEncrypt(_serverPublicKey, _outputStream, testData, _bufferStream, _compressionAlgorithm, _symmetricEncryptionAlgorithm, _asymmetricEncryptionAlgorithm, CancellationToken.None);

        // Assert
        eventPackerServiceBuilder.CompressorFactory.Received(1).CreatePlugin(_compressionAlgorithm);
        eventPackerServiceBuilder.AsymmetricEncryptorFactory.Received(1).CreatePlugin(_asymmetricEncryptionAlgorithm);
        eventPackerServiceBuilder.SymmetricEncryptorFactory.Received(1).CreatePlugin(_symmetricEncryptionAlgorithm);
    }

    [Fact]
    public async Task CompressAndEncryptCallsEncryptSessionKeyAndReturnsEncryptedKey()
    {
        // Arrange
        var expectedEncryptedKey = new byte[] { 1, 2, 3, 4, 5 };
        var eventPackerServiceBuilder = new EventPackerServiceBuilder();

        var mockAsymmetricEncryptor = Substitute.For<IAsymmetricEncryptor>();
        mockAsymmetricEncryptor.EncryptSessionKey(Arg.Any<byte[]>(), Arg.Any<byte[]>())
            .Returns(expectedEncryptedKey);

        eventPackerServiceBuilder.AsymmetricEncryptorFactory
            .CreatePlugin(_asymmetricEncryptionAlgorithm)
            .Returns(mockAsymmetricEncryptor);

        var service = eventPackerServiceBuilder.Build();
        var testData = new MemoryStream();

        // Act
        var result = await service.CompressAndEncrypt(_serverPublicKey, _outputStream, testData, _bufferStream, _compressionAlgorithm, _symmetricEncryptionAlgorithm, _asymmetricEncryptionAlgorithm, CancellationToken.None);

        // Assert
        mockAsymmetricEncryptor.Received(1).EncryptSessionKey(_serverPublicKey, Arg.Any<byte[]>());
        Assert.Equal(expectedEncryptedKey, result.EncryptedKey);
    }

    [Fact]
    public async Task CompressAndEncryptCallsSymmetricEncryptWithCorrectDataAndReturnsEncryptedData()
    {
        // Arrange
        var expectedCompressedData = new byte[] { 10, 20, 30 };
        var expectedSessionKey = new byte[] { 5, 6, 7, 8 };
        var expectedEncryptedData = new byte[] { 100, 101, 102 };
        var eventPackerServiceBuilder = new EventPackerServiceBuilder();

        var mockCompressor = Substitute.For<ICompressor>();
        mockCompressor.Compress(Arg.Any<Stream>(), Arg.Any<Stream>())
            .Returns(Task.CompletedTask);

        var mockSymmetricEncryptor = Substitute.For<ISymmetricEncryptor>();
        mockSymmetricEncryptor.GenerateKey()
            .Returns(expectedSessionKey);
        mockSymmetricEncryptor.EncryptStreamAsync(Arg.Any<Stream>(), Arg.Any<Stream>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);

        eventPackerServiceBuilder.CompressorFactory
            .CreatePlugin(_compressionAlgorithm)
            .Returns(mockCompressor);

        eventPackerServiceBuilder.SymmetricEncryptorFactory
            .CreatePlugin(_symmetricEncryptionAlgorithm)
            .Returns(mockSymmetricEncryptor);

        var service = eventPackerServiceBuilder.Build();
        var testData = new MemoryStream();

        // Act
        var result = await service.CompressAndEncrypt(_serverPublicKey, _outputStream, testData, _bufferStream, _compressionAlgorithm, _symmetricEncryptionAlgorithm, _asymmetricEncryptionAlgorithm, CancellationToken.None);

        // Assert
        await mockSymmetricEncryptor.Received(1).EncryptStreamAsync(_bufferStream, _outputStream, expectedSessionKey, Arg.Any<CancellationToken>());
       
    }

    [Fact]
    public async Task CompressAndEncryptCallsCompressorWithCorrectData()
    {
        // Arrange
        var expectedCompressedData = new byte[] { 10, 20, 30 };
        var eventPackerServiceBuilder = new EventPackerServiceBuilder();
        var mockCompressor = Substitute.For<ICompressor>();
        mockCompressor.Compress(Arg.Any<Stream>(), Arg.Any<Stream>())
            .Returns(Task.FromResult(expectedCompressedData));

        eventPackerServiceBuilder.CompressorFactory
            .CreatePlugin(_compressionAlgorithm)
            .Returns(mockCompressor);
        var service = eventPackerServiceBuilder.Build();
        var testData = new MemoryStream();
        // Act
        await service.CompressAndEncrypt(_serverPublicKey, _outputStream, testData, _bufferStream, _compressionAlgorithm, _symmetricEncryptionAlgorithm, _asymmetricEncryptionAlgorithm, CancellationToken.None);

        // Assert
        await mockCompressor.Received(1).Compress(testData, _bufferStream);
    }

    public void Dispose()
    {
        _bufferStream.Dispose();
        _outputStream.Dispose();
    }
}
