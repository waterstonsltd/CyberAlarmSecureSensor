namespace CyberAlarm.SyslogRelay.Domain.Upload.Scheduling;

public sealed class ScheduleOptions
{
    public int UploadIntervalInMinutes { get; init; } = 60;

    /// <summary>
    /// Upload interval used before the first successful upload.
    /// This allows new sensors to appear online quickly in the portal.
    /// </summary>
    public int InitialUploadIntervalInMinutes { get; init; } = 2;

    public TimeSpan UploadInterval => TimeSpan.FromMinutes(UploadIntervalInMinutes);

    public TimeSpan InitialUploadInterval => TimeSpan.FromMinutes(InitialUploadIntervalInMinutes);
}
