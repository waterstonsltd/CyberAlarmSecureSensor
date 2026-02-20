using System.Security.Cryptography;
using CyberAlarm.EventBundler.Plugins.Signers;
using CyberAlarm.SyslogRelay.Common.EventBundler.Models;
using CyberAlarm.SyslogRelay.Common.EventBundler.Plugins;
using CyberAlarm.SyslogRelay.Common.EventBundler.Settings;
using Microsoft.Extensions.Logging;
using System.Text.Json;
using System.Threading;

namespace CyberAlarm.EventBundler.Services;

/// <summary>
/// Service responsible for bundling and unbundling encrypted, compressed, and signed event data.
/// </summary>
public sealed class EventBundlerService : IEventBundlerService
{
    private const string _EnvelopeVersion = "1.0";
    private const string _BundlerVersion = "1.0";

    private readonly IPluginFactory<ISigner> _signerFactory;
    private readonly IEventPackerService _eventPacker;

    private readonly ILogger<EventBundlerService> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="EventBundlerService"/> class.
    /// </summary>
    /// <param name="signerFactory">Factory for creating signing plugin instances.</param>
    /// <param name="eventPacker">Service for compressing, encrypting, and decrypting event data.</param>
    /// <param name="logger">Logger instance for logging operations.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="signerFactory"/>, <paramref name="eventPacker"/>, or <paramref name="logger"/> is null.</exception>
    public EventBundlerService(IPluginFactory<ISigner> signerFactory, IEventPackerService eventPacker, ILogger<EventBundlerService> logger)
    {
        _signerFactory = signerFactory ?? throw new ArgumentNullException(nameof(signerFactory));
        _eventPacker = eventPacker ?? throw new ArgumentNullException(nameof(eventPacker));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Bundles events into an encrypted, compressed, and signed event bundle.
    /// </summary>
    /// <param name="outputBundle">The output stream where the final event bundle will be written.</param>
    /// <param name="data">The events to bundle.</param>
    /// <param name="bufferStream">Used as a buffer when we compress the data. Can be a memory stream if there is plenty of memory available, or a file stream to keep memory usages predictable.</param>
    /// <param name="relayId">The unique identifier of the relay.</param>
    /// <param name="buildVersion">The build version of the relay.</param>
    /// <param name="platform">The platform on which the relay is running.</param>
    /// <param name="syslogRelayPrivateKey">The RSA private key of the syslog relay used for signing.</param>
    /// <param name="serverPublicKey">The RSA public key of the server used for encryption.</param>
    /// <param name="options">Options specifying compression, encryption, and signing algorithms.</param>
    /// <param name="cancellationToken">A token to monitor for cancellation requests.</param> 
    /// <returns>A task that represents the asynchronous operation.</returns>
    public async Task<EventBundle> BundleAsync(Stream outputBundle, Stream data, Stream bufferStream, string relayId, string buildVersion, Platform platform, byte[] syslogRelayPrivateKey, byte[] serverPublicKey, BundleOptions options, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Starting event bundle creation for relay {RelayId}", relayId);

        ValidateRsaKeySize(syslogRelayPrivateKey, "syslogRelayPrivateKey");
        ValidateRsaKeySize(serverPublicKey, "serverPublicKey");

        var syslogRelayThumbprint = ComputePublicKeyThumbprint(syslogRelayPrivateKey);

        var serverThumbprint = ComputePublicKeyThumbprint(serverPublicKey);

        outputBundle.Position = BundleHeader.HeaderSize; // Reserve space for header
        
        RelayMetaData metaData = new RelayMetaData(relayId, buildVersion, platform, syslogRelayThumbprint);
        Server server = new Server(serverThumbprint);

        _logger.LogDebug(
            "Compressing and encrypting event data using {CompressionAlgorithm}, {SymmetricEncryption}, {AsymmetricEncryption}",
            options.CompressionAlgorithm,
            options.SymmetricEncryptionAlgorithm,
            options.AsymmetricEncryptionAlgorithm);

        Encryption encryptionMetaData = await _eventPacker.CompressAndEncrypt(serverPublicKey, outputBundle, data, bufferStream, options.CompressionAlgorithm, options.SymmetricEncryptionAlgorithm, options.AsymmetricEncryptionAlgorithm, cancellationToken);

        byte[] nonce = RandomNumberGenerator.GetBytes(32);

        Document document = new Document(_BundlerVersion, metaData, server, encryptionMetaData, DateTime.UtcNow, nonce);

        _logger.LogDebug("Signing document using {SigningAlgorithm}", options.SigningAlgorithm);

        var signer = _signerFactory.CreatePlugin(options.SigningAlgorithm);

        ulong startOfJson = (ulong)outputBundle.Position;

        Signature signatureModel = new Signature(signer.AlgorithmName);

        Envelope envelope = new Envelope(_EnvelopeVersion, signatureModel);
        EventBundle eventBundle = new EventBundle(envelope, document);

        // Serialize directly to file
        await JsonSerializer.SerializeAsync(outputBundle, eventBundle, cancellationToken: cancellationToken);

        ulong startOfSignature = (ulong)outputBundle.Position;

        BundleHeader header = new BundleHeader()
        {
            MagicNumber = BundleHeader.Magic,
            VersionNumber = BundleHeader.Version,
            JsonLength = (uint)(startOfSignature - startOfJson),
            PayloadLength = startOfJson - BundleHeader.HeaderSize,
            SignatureLength = signer.SignatureSize
        };

        // Reset to beginning for signing
        outputBundle.Position = 0;

        header.WriteTo(outputBundle);

        outputBundle.Position = 0;

        // Sign from stream
        var signature = signer.Sign(syslogRelayPrivateKey, outputBundle);

        outputBundle.Position = (long) startOfSignature;
        await outputBundle.WriteAsync(signature, cancellationToken);

        _logger.LogInformation("Successfully created event bundle for relay {RelayId}", relayId);

        return eventBundle;
    }

    /// <summary>
    /// Computes the SHA256 thumbprint of an RSA public key.
    /// </summary>
    /// <param name="keyData">The RSA key instance.</param>
    /// <returns>A hexadecimal string representation of the public key thumbprint.</returns>
    private static string ComputePublicKeyThumbprint(byte[] keyData)
    {
        var key = RSA.Create();
        try
        {
            key.ImportRSAPrivateKey(keyData, out _);
        }
        catch
        {
            key.ImportRSAPublicKey(keyData, out _);
        }

        var publicKey = key.ExportSubjectPublicKeyInfo();
        var hash = SHA256.HashData(publicKey);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Validates that an RSA key is 4096 bits in size.
    /// </summary>
    /// <param name="keyData">The RSA key data to validate.</param>
    /// <param name="parameterName">The name of the parameter being validated.</param>
    /// <exception cref="ArgumentException">Thrown when the key size is not 4096 bits.</exception>
    private static void ValidateRsaKeySize(byte[] keyData, string parameterName)
    {
        using var rsa = RSA.Create();
        try
        {
            rsa.ImportRSAPrivateKey(keyData, out _);
        }
        catch
        {
            rsa.ImportRSAPublicKey(keyData, out _);
        }

        if (rsa.KeySize != 4096)
        {
            throw new ArgumentException($"RSA key must be 4096 bits. Provided key is {rsa.KeySize} bits.", parameterName);
        }
    }
}
