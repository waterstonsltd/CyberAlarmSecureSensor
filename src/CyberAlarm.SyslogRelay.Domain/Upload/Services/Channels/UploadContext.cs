using CyberAlarm.SyslogRelay.Common.Status.Models;

namespace CyberAlarm.SyslogRelay.Domain.Upload.Services.Channels;

internal sealed record UploadContext(
    string StorageAccountName,
    string PrivateKeyPem,
    RelayStatus Status,
    RelayOptions RelayOptions)
{
    private const string StorageAccountDomain = "blob.core.windows.net";

    public string TargetServer => $"{StorageAccountName}.{StorageAccountDomain}";

    public string UserName => $"{StorageAccountName}.{RelayOptions.UserName}";
}
