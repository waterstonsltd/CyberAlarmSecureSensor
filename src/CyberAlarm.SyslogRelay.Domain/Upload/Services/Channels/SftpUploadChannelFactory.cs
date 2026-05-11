using CyberAlarm.SyslogRelay.Common.Status.Models;
using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Domain.State;
using CyberAlarm.SyslogRelay.Domain.Upload.Infrastructure;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Upload.Services.Channels;

internal sealed class SftpUploadChannelFactory(
    ISecureFtpClientFactory secureFtpClientFactory,
    IFileManager fileManager,
    IApplicationManager applicationManager,
    IStateService stateService,
    UploadMetrics uploadMetrics,
    ILogger<SftpUploadChannelFactory> logger)
    : IUploadChannelFactory
{
    public IUploadChannel Create(UploadContext context)
    {
        var hostFingerprints = new List<string> { context.Status.HostFingerprint };
        if (context.Status.SecondaryHostFingerprint is not null)
        {
            hostFingerprints.Add(context.Status.SecondaryHostFingerprint);
        }

        var client = secureFtpClientFactory.Create(context.TargetServer, context.UserName, context.PrivateKeyPem, hostFingerprints);
        return new SftpUploadChannel(client, fileManager, applicationManager, stateService, uploadMetrics, logger);
    }
}
