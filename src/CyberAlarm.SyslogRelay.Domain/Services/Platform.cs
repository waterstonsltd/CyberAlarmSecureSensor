namespace CyberAlarm.SyslogRelay.Domain.Services;

public record Platform(
    string Os,
    string Runtime,
    string Architecture,
    bool RunningInContainer);
