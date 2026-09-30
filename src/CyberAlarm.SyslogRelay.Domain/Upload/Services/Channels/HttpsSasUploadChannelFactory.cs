using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Domain.State;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Upload.Services.Channels;

internal sealed class HttpsSasUploadChannelFactory(
    IHttpClientFactory httpClientFactory,
    IFileManager fileManager,
    IApplicationManager applicationManager,
    IStateService stateService,
    UploadMetrics uploadMetrics,
    ILogger<HttpsSasUploadChannelFactory> logger)
    : IUploadChannelFactory
{
    public IUploadChannel Create(UploadContext context) =>
        new HttpsSasUploadChannel(
            httpClientFactory,
            context,
            fileManager,
            applicationManager,
            stateService,
            uploadMetrics,
            logger);
}
