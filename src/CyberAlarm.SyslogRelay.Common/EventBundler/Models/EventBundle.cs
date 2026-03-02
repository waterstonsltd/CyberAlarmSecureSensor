namespace CyberAlarm.SyslogRelay.Common.EventBundler.Models;

public record EventBundle(
    Envelope Envelope,
    Document Document);
