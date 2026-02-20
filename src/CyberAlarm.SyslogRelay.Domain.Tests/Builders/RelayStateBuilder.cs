using CyberAlarm.SyslogRelay.Domain.State;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class RelayStateBuilder
{
    private readonly string _statusETag = Guid.NewGuid().ToString();

    private bool _isRegistered = true;
    private bool _isUploadBlocked;
    private string _registrationToken = "1.x.x";

    public RelayState Build() => new(_isRegistered, _isUploadBlocked, _statusETag, _registrationToken);

    public RelayStateBuilder WithIsRegistered(bool isRegistered)
    {
        _isRegistered = isRegistered;
        return this;
    }

    public RelayStateBuilder WithIsUploadBlocked(bool isUploadBlocked)
    {
        _isUploadBlocked = isUploadBlocked;
        return this;
    }

    public RelayStateBuilder WithRegistrationToken(string registrationToken)
    {
        _registrationToken = registrationToken;
        return this;
    }
}
