namespace CyberAlarm.SyslogRelay.Common.EventBundler.Models;

public record Encryption(
    byte[] EncryptedKey,
    string KeyEncryptionAlgorithm,
    string DataEncryptionAlgorithm,
    string CompressionAlgorithm);
