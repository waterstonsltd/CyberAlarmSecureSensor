namespace CyberAlarm.SyslogRelay.Domain.HealthCheck;

internal sealed record HealthCheckEntry(DateTime Timestamp, HealthStatus Status);
