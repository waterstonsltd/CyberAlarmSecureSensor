namespace CyberAlarm.SyslogRelay.Domain.Upload.Scheduling;

public sealed class ScheduleOptions
{
    public int UploadIntervalInMinutes { get; init; } = 60;

    public TimeSpan UploadInterval => TimeSpan.FromMinutes(UploadIntervalInMinutes);
}
