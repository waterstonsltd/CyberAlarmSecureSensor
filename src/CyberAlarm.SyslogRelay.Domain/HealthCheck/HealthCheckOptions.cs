namespace CyberAlarm.SyslogRelay.Domain.HealthCheck;

internal sealed class HealthCheckOptions
{
    public string[] ServicesToRegister { get; set; } = [];
}
