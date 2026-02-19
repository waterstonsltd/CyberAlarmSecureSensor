namespace CyberAlarm.SyslogRelay.Domain.Status;

public sealed class RelayStatus
{
    public bool UploadsDisabled { get; init; }

    public required string MinimumSupportedVersion { get; init; }

    public required string CurrentVersion { get; init; }

    public required IDictionary<string, string> StorageAccounts { get; init; }

    public required string RegistrationEndpoint { get; init; }

    public required string HostFingerprint { get; init; }

    public required string ServerPublicKey { get; init; }

    public LogParser[] Parsers { get; init; } = [];
}
