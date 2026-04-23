using CyberAlarm.SyslogRelay.Domain.Registration;
using CyberAlarm.SyslogRelay.Domain.Services;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class RegistrationRequestBuilder
{
    private readonly string _publicKey = Guid.NewGuid().ToString();
    private readonly string _registrationToken = "1.xxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxx";
    private readonly string _syslogRelayBuildVersion = "1.0.0";
    private readonly Platform _syslogRelayPlatform = new(
        Guid.NewGuid().ToString(),
        Guid.NewGuid().ToString(),
        Guid.NewGuid().ToString(),
        false);

    public RegistrationRequest Build() =>
        new()
        {
            PublicKey = _publicKey,
            RegistrationToken = _registrationToken,
            SyslogRelayBuildVersion = _syslogRelayBuildVersion,
            SyslogRelayPlatform = _syslogRelayPlatform,
        };
}
