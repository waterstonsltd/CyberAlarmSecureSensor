namespace CyberAlarm.SyslogRelay.Common.EventBundler.Models;

public record RelayMetaData(
    string Id,
    string Version,
    Platform Platform,
    string PublicKeyFingerprint);
