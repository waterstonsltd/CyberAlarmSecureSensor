using CyberAlarm.SyslogRelay.Domain.Extensions;
using Microsoft.Extensions.Configuration;

namespace CyberAlarm.SyslogRelay.Domain;

public sealed class RelayOptions
{
    public string BuildVersion { get; init; } = string.Empty;

    public bool EnableRequestLogging { get; init; }

    public bool TlsEnabled { get; init; }

    public bool AllowPlaintextListenersWhenTlsEnabled { get; init; }

    public string TlsCertificatePath { get; init; } = string.Empty;

    public string TlsCertificatePassword { get; init; } = string.Empty;

    public bool TlsRequireClientCertificate { get; init; }

    public string TlsClientCaCertificatePath { get; init; } = string.Empty;

    public int TlsPort { get; init; } = 6514;

    public bool FileWatcherEnabled { get; init; }

    public string FileWatcherDropPath { get; init; } = string.Empty;

    public int FileWatcherIntervalInSeconds { get; init; }

    public int FileWatcherMaximumRetryCount { get; init; }

    public int MaximumTcpClients { get; init; }

    public int PatternMatchingScanLength { get; init; }

    public int PatternMatchingCacheDurationInSeconds { get; init; }

    [ConfigurationKeyName("REGISTRATION_TOKEN")]
    public string RegistrationToken { get; init; } = string.Empty;

    public string ApiBaseUrl { get; init; } = string.Empty;

    public string StatusEndpoint => $"{ApiBaseUrl}/api/v1/SyslogRelayStatus";

    public string RegistrationEndpoint => $"{ApiBaseUrl}/api/v1/SyslogRelay/register";

    public int RsaKeySize { get; } = 4096;

    public int TcpPort { get; } = 514;

    public int UdpPort { get; } = 514;

    public string Bucket => RegistrationToken.SelectElement(0, '.');

    public object UserName => RegistrationToken.SelectElement(1, '.');

    public string RelayId => $"{Bucket}.{UserName}";

    public long RawGroupedLogsMaxFileSizeBytes { get; init; } = 500 * 1024 * 1024;
}
