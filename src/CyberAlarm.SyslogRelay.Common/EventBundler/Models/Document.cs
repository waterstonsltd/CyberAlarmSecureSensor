namespace CyberAlarm.SyslogRelay.Common.EventBundler.Models;

public record Document(
    string Version,
    RelayMetaData Relay,
    Server Server,
    Encryption Encryption,
    DateTime Timestamp,
    byte[] Nonce);
