namespace CyberAlarm.SyslogRelay.Domain.State;

public sealed record RelayState(
    bool IsRegistered,
    bool IsUploadBlocked,
    string StatusETag,
    string RegistrationToken)
{
    public static readonly RelayState Empty = new(
        false,
        false,
        string.Empty,
        string.Empty);
}
