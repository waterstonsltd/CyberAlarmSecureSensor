namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class RelayOptionsBuilder
{
    private string _buildVersion = "1.0.0";
    private bool _tlsEnabled;
    private bool _allowPlaintextListenersWhenTlsEnabled;
    private string _tlsCertificatePath = string.Empty;
    private string _tlsCertificatePassword = string.Empty;
    private bool _tlsRequireClientCertificate;
    private string _tlsClientCaCertificatePath = string.Empty;
    private int _tlsPort = 6514;
    private bool _fileWatcherEnabled;
    private string _fileWatcherDropPath = Guid.NewGuid().ToString();
    private int _fileWatcherMaximumRetryCount = 5;
    private int _maximumTcpClients = 3;
    private string _registrationToken = "1.xxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxx";
    private string _apiBaseUrl = "https://example.com";
    private int _patternMatchingCacheDurationInSeconds;
    private int _patternMatchingScanLength = 300;

    public RelayOptions Build() =>
        new()
        {
            BuildVersion = _buildVersion,
            TlsEnabled = _tlsEnabled,
            AllowPlaintextListenersWhenTlsEnabled = _allowPlaintextListenersWhenTlsEnabled,
            TlsCertificatePath = _tlsCertificatePath,
            TlsCertificatePassword = _tlsCertificatePassword,
            TlsRequireClientCertificate = _tlsRequireClientCertificate,
            TlsClientCaCertificatePath = _tlsClientCaCertificatePath,
            TlsPort = _tlsPort,
            FileWatcherEnabled = _fileWatcherEnabled,
            FileWatcherDropPath = _fileWatcherDropPath,
            FileWatcherMaximumRetryCount = _fileWatcherMaximumRetryCount,
            MaximumTcpClients = _maximumTcpClients,
            RegistrationToken = _registrationToken,
            ApiBaseUrl = _apiBaseUrl,
            PatternMatchingCacheDurationInSeconds = _patternMatchingCacheDurationInSeconds,
            PatternMatchingScanLength = _patternMatchingScanLength,
        };

    public RelayOptionsBuilder WithBuildVersion(string buildVerison)
    {
        _buildVersion = buildVerison;
        return this;
    }

    public RelayOptionsBuilder WithTlsEnabled(bool tlsEnabled)
    {
        _tlsEnabled = tlsEnabled;
        return this;
    }

    public RelayOptionsBuilder WithAllowPlaintextListenersWhenTlsEnabled(bool allowPlaintextListenersWhenTlsEnabled)
    {
        _allowPlaintextListenersWhenTlsEnabled = allowPlaintextListenersWhenTlsEnabled;
        return this;
    }

    public RelayOptionsBuilder WithTlsCertificatePath(string tlsCertificatePath)
    {
        _tlsCertificatePath = tlsCertificatePath;
        return this;
    }

    public RelayOptionsBuilder WithTlsCertificatePassword(string tlsCertificatePassword)
    {
        _tlsCertificatePassword = tlsCertificatePassword;
        return this;
    }

    public RelayOptionsBuilder WithTlsRequireClientCertificate(bool tlsRequireClientCertificate)
    {
        _tlsRequireClientCertificate = tlsRequireClientCertificate;
        return this;
    }

    public RelayOptionsBuilder WithTlsClientCaCertificatePath(string tlsClientCaCertificatePath)
    {
        _tlsClientCaCertificatePath = tlsClientCaCertificatePath;
        return this;
    }

    public RelayOptionsBuilder WithTlsPort(int tlsPort)
    {
        _tlsPort = tlsPort;
        return this;
    }

    public RelayOptionsBuilder WithFileWatcherDropPath(string fileWatcherDropPath)
    {
        _fileWatcherDropPath = fileWatcherDropPath;
        return this;
    }

    public RelayOptionsBuilder WithFileWatcherEnabled(bool fileWatcherEnabled)
    {
        _fileWatcherEnabled = fileWatcherEnabled;
        return this;
    }

    public RelayOptionsBuilder WithFileWatcherMaximumRetryCount(int fileWatcherMaximumRetryCount)
    {
        _fileWatcherMaximumRetryCount = fileWatcherMaximumRetryCount;
        return this;
    }

    public RelayOptionsBuilder WithRegistrationToken(string registrationToken)
    {
        _registrationToken = registrationToken;
        return this;
    }

    public RelayOptionsBuilder WithMaximumTcpClients(int maximumTcpClients)
    {
        _maximumTcpClients = maximumTcpClients;
        return this;
    }

    public RelayOptionsBuilder WithApiBaseUrl(string apiBaseUrl)
    {
        _apiBaseUrl = apiBaseUrl;
        return this;
    }

    public RelayOptionsBuilder WithPatternMatchingCacheDurationInSeconds(int seconds)
    {
        _patternMatchingCacheDurationInSeconds = seconds;
        return this;
    }

    public RelayOptionsBuilder WithPatternMatchingScanLength(int scanLength)
    {
        _patternMatchingScanLength = scanLength;
        return this;
    }
}
