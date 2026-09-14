namespace CyberAlarm.SyslogRelay.Domain.HealthCheck;

public sealed record HealthCheckResult(HealthStatus Status, string? Reason);
