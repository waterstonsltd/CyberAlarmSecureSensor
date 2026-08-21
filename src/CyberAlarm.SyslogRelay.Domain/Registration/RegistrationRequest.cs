using System.Text.Json;
using CyberAlarm.SyslogRelay.Domain.Services;

namespace CyberAlarm.SyslogRelay.Domain.Registration;

public sealed class RegistrationRequest
{
    public required string PublicKey { get; init; }

    public required string RegistrationToken { get; init; }

    public required string SyslogRelayBuildVersion { get; init; }

    public required Platform SyslogRelayPlatform { get; init; }

    public override string ToString() => JsonSerializer.Serialize(this);
}
