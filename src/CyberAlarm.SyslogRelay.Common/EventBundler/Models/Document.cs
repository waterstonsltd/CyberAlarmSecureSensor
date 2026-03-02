namespace CyberAlarm.SyslogRelay.Common.EventBundler.Models;

public record Document(
    string Version,
    RelayMetaData Relay,
    Server Server,
    Encryption Encryption,
    EventsMetaData EventsMetaData,
    DateTime Timestamp,
    byte[] Nonce);
