using CyberAlarm.SyslogRelay.Domain.Upload.Services;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Upload.Services;

public class UploadResultTests
{
    [Fact]
    public void Empty_ReturnsZeroCounts()
    {
        var result = UploadResult.Empty;

        Assert.Equal(0, result.FilesUploaded);
        Assert.Equal(0, result.FilesFailed);
    }

    [Fact]
    public void Empty_HasUploads_ReturnsFalse()
    {
        var result = UploadResult.Empty;

        Assert.False(result.HasUploads);
    }

    [Theory]
    [InlineData(0, 0, false)]
    [InlineData(0, 5, false)]
    [InlineData(1, 0, true)]
    [InlineData(5, 2, true)]
    public void HasUploads_ReturnsCorrectValue(int uploaded, int failed, bool expected)
    {
        var result = new UploadResult(uploaded, failed);

        Assert.Equal(expected, result.HasUploads);
    }

    [Fact]
    public void Constructor_SetsProperties()
    {
        var result = new UploadResult(10, 3);

        Assert.Equal(10, result.FilesUploaded);
        Assert.Equal(3, result.FilesFailed);
    }
}
