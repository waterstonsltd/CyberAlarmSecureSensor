namespace CyberAlarm.SyslogRelay.Common.EventBundler.Models;

public record Envelope(
    string Version,
    Signature Signature);
