namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class RelayOptionsBuilder
{
    private string _buildVersion = "1.0.0";
    private bool _fileWatcherEnabled;
    private string _fileWatcherDropPath = Guid.NewGuid().ToString();
    private int _fileWatcherMaximumRetryCount = 5;
    private string _registrationToken = "1.xxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxx";
    private string _apiBaseUrl = "https://example.com";

    public RelayOptions Build() =>
        new()
        {
            BuildVersion = _buildVersion,
            FileWatcherEnabled = _fileWatcherEnabled,
            FileWatcherDropPath = _fileWatcherDropPath,
            FileWatcherMaximumRetryCount = _fileWatcherMaximumRetryCount,
            RegistrationToken = _registrationToken,
            ApiBaseUrl = _apiBaseUrl,
        };

    public RelayOptionsBuilder WithBuildVersion(string buildVerison)
    {
        _buildVersion = buildVerison;
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

    public RelayOptionsBuilder WithApiBaseUrl(string apiBaseUrl)
    {
        _apiBaseUrl = apiBaseUrl;
        return this;
    }
}
