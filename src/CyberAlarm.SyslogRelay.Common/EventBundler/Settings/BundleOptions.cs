namespace CyberAlarm.SyslogRelay.Common.EventBundler.Settings;

/// <summary>
/// Represents the configuration options for bundling events, including algorithms for signing, encryption, and compression.
/// </summary>
public class BundleOptions
{
    /// <summary>
    /// Gets or sets the signing algorithm to use for event bundles.
    /// Defaults to RSA-PSS with SHA-256.
    /// </summary>
    public string SigningAlgorithm { get; set; } = SupportedAlgorithms.Signers.RsaPssSha256;

    /// <summary>
    /// Gets or sets the asymmetric encryption algorithm to use for event bundles.
    /// Defaults to RSA-OAEP with SHA-256.
    /// </summary>
    public string AsymmetricEncryptionAlgorithm { get; set; } = SupportedAlgorithms.Encryptors.RsaOaepSha256;

    /// <summary>
    /// Gets or sets the symmetric encryption algorithm to use for event bundles.
    /// Defaults to AES-256-GCM.
    /// </summary>
    public string SymmetricEncryptionAlgorithm { get; set; } = SupportedAlgorithms.Encryptors.Aes256GcmChunked;

    /// <summary>
    /// Gets or sets the compression algorithm to use for event bundles.
    /// Defaults to Brotli compression.
    /// </summary>
    public string CompressionAlgorithm { get; set; } = SupportedAlgorithms.Compressors.Brotli;
}
