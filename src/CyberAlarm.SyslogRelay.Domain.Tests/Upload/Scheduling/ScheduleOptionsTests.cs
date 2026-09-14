using CyberAlarm.SyslogRelay.Domain.Upload.Scheduling;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Upload.Scheduling;

public sealed class ScheduleOptionsTests
{
    [Fact]
    public void UploadIntervalInMinutes_DefaultsTo60()
    {
        var options = new ScheduleOptions();

        Assert.Equal(60, options.UploadIntervalInMinutes);
    }

    [Fact]
    public void InitialUploadIntervalInMinutes_DefaultsTo2()
    {
        var options = new ScheduleOptions();

        Assert.Equal(2, options.InitialUploadIntervalInMinutes);
    }

    [Fact]
    public void UploadInterval_ReturnsTimeSpanFromMinutes()
    {
        var options = new ScheduleOptions { UploadIntervalInMinutes = 30 };

        Assert.Equal(TimeSpan.FromMinutes(30), options.UploadInterval);
    }

    [Fact]
    public void InitialUploadInterval_ReturnsTimeSpanFromMinutes()
    {
        var options = new ScheduleOptions { InitialUploadIntervalInMinutes = 5 };

        Assert.Equal(TimeSpan.FromMinutes(5), options.InitialUploadInterval);
    }
}
