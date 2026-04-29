using CyberAlarm.SyslogRelay.Common.EventBundler.Plugins;

namespace CyberAlarm.EventBundler.Plugins.Signers;

/// <summary>
/// Defines a plugin interface for cryptographic signing and signature verification operations.
/// </summary>
/// <typeparam name="TPrivateKey">The type representing the private key used for signing operations.</typeparam>
/// <typeparam name="TPublicKey">The type representing the public key used for signature verification operations.</typeparam>
public interface ISigner : IPlugin
{
    /// <summary>
    /// Signs the specified data using the provided private key.
    /// </summary>
    /// <param name="key">The private key used for signing.</param>
    /// <param name="dataToSign">The data to be signed.</param>
    /// <returns>
    /// A byte array containing the cryptographic signature of the provided data.
    /// </returns>
    byte[] Sign(byte[] key, Stream dataToSign);

    /// <summary>
    /// Gets the size, in bytes, of the digital signature.
    /// </summary>
    public ushort SignatureSize { get; }
}
