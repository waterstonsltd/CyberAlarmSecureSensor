namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class RelayOptionsBuilder
{
    private string _buildVersion = "1.0.0";
    private string _fileWatcherDropPath = Guid.NewGuid().ToString();
    private int _fileWatcherMaximumRetryCount = 5;
    private string _registrationToken = "1.xxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxx";
    private string _statusEndpoint = "http://example.com/status";

    public RelayOptions Build() =>
        new()
        {
            BuildVersion = _buildVersion,
            FileWatcherDropPath = _fileWatcherDropPath,
            FileWatcherMaximumRetryCount = _fileWatcherMaximumRetryCount,
            RegistrationToken = _registrationToken,
            StatusEndpoint = _statusEndpoint,
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

    public RelayOptionsBuilder WithStatusEndpoint(string statusEndpoint)
    {
        _statusEndpoint = statusEndpoint;
        return this;
    }
}
