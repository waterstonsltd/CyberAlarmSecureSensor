using CyberAlarm.SyslogRelay.Domain.Extensions;
using Microsoft.Extensions.Configuration;

namespace CyberAlarm.SyslogRelay.Domain;

public sealed class RelayOptions
{
    public string BuildVersion { get; init; } = string.Empty;

    public bool EnableRequestLogging { get; init; }

    public string FileWatcherDropPath { get; init; } = string.Empty;

    public int FileWatcherIntervalInSeconds { get; init; }

    public int FileWatcherMaximumRetryCount { get; init; }

    public int MaximumTcpClients { get; init; }

    [ConfigurationKeyName("REGISTRATION_TOKEN")]
    public string RegistrationToken { get; init; } = string.Empty;

    public string StatusEndpoint { get; init; } = string.Empty;

    public int RsaKeySize { get; } = 4096;

    public int TcpPort { get; } = 514;

    public int UdpPort { get; } = 514;

    public string Bucket => RegistrationToken.SelectElement(0, '.');

    public object UserName => RegistrationToken.SelectElement(1, '.');

    public string RelayId => $"{Bucket}.{UserName}";

    public long RawGroupedLogsMaxFileSizeBytes { get; init; } = 500 * 1024 * 1024;
}
