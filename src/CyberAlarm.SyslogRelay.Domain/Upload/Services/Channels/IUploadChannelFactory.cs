namespace CyberAlarm.SyslogRelay.Domain.Upload.Services.Channels;

internal interface IUploadChannelFactory
{
    IUploadChannel Create(UploadContext context);
}
