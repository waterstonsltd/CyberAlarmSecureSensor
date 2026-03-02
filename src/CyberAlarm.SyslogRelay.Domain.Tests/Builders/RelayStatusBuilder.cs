using CyberAlarm.SyslogRelay.Common.Status.Models;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class RelayStatusBuilder
{
    private readonly string _registrationEndpoint = "https://example.com/register";
    private readonly string _hostFingerprint = Guid.NewGuid().ToString();
    private string _serverPublicKey = Guid.NewGuid().ToString();
    private readonly Dictionary<string, string> _storageAccounts = new()
    {
        ["1"] = "sa001",
        ["2"] = "sa002",
        ["3"] = "sa003",
    };

    private bool _uploadsDisabled;
    private string _minimumSupportedVersion = "1.0.0";
    private string _currentVersion = "1.0.0";

    public RelayStatus Build() =>
        new()
        {
            UploadsDisabled = _uploadsDisabled,
            MinimumSupportedVersion = _minimumSupportedVersion,
            CurrentVersion = _currentVersion,
            StorageAccounts = _storageAccounts,
            RegistrationEndpoint = _registrationEndpoint,
            HostFingerprint = _hostFingerprint,
            ServerPublicKey = _serverPublicKey,
        };

    public RelayStatusBuilder WithUploadsDisabled(bool uploadsDisabled)
    {
        _uploadsDisabled = uploadsDisabled;
        return this;
    }

    public RelayStatusBuilder WithMinimumSupportedVersion(string minimumSupportedVersion)
    {
        _minimumSupportedVersion = minimumSupportedVersion;
        return this;
    }

    public RelayStatusBuilder WithCurrentVersion(string currentVersion)
    {
        _currentVersion = currentVersion;
        return this;
    }

    public RelayStatusBuilder WithServerPublicKey(string serverPublicKey)
    {
        _serverPublicKey = serverPublicKey;
        return this;
    }
}
