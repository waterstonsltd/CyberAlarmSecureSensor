using CyberAlarm.SyslogRelay.Common.EventBundler.Plugins;

namespace CyberAlarm.EventBundler.Plugins.Encryptors;

/// <summary>
/// Defines a plugin for asymmetric encryption operations used to protect session keys.
/// </summary>
public interface IAsymmetricEncryptor : IPlugin
{
    /// <summary>
    /// Encrypts a session key using the specified public key parameters.
    /// </summary>
    /// <param name="key">The public key parameters used for encryption.</param>
    /// <param name="unprotectedKey">The unencrypted session key bytes to protect.</param>
    /// <returns>The encrypted session key bytes.</returns>
    public byte[] EncryptSessionKey(byte[] key, byte[] unprotectedKey);
}
