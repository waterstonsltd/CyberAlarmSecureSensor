namespace CyberAlarm.SyslogRelay.Common.EventBundler.Models;

public record Platform(
    string Os,
    string Runtime,
    string Architecture);
