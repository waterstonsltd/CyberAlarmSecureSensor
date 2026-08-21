using CyberAlarm.SyslogRelay.Domain.Ingestion;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Ingestion;

public sealed class MarkedFileTests
{

    [Fact]
    public void Create_should_throw_when_name_is_empty()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => MarkedFile.Create(string.Empty));
    }

    [Theory]
    [InlineData("x", 0)]
    [InlineData(".x", 0)]
    [InlineData("x.x", 0)]
    [InlineData("1", 0)]
    [InlineData("1.x", 0)]
    [InlineData("~", 0)]
    [InlineData("~x", 0)]
    [InlineData("~.x", 0)]
    [InlineData("~1", 0)]
    [InlineData("~11", 0)]
    [InlineData("~1.x", 1)]
    [InlineData("~11.x", 11)]
    [InlineData("~1.xx", 1)]
    [InlineData("~11.xx", 11)]
    [InlineData("~1.x.x", 1)]
    [InlineData("~1.x~1.x", 1)]
    public void Create_should_return_markedFile_with_valid_retryCount_from_fileName(string fileName, int expected)
    {
        // Arrange
        var markedFile = MarkedFile.Create(fileName);

        // Act & Assert
        Assert.Equal(expected, markedFile.RetryCount);
    }

    [Theory]
    [InlineData("x", "~1.x")]
    [InlineData(".x", "~1..x")]
    [InlineData("x.x", "~1.x.x")]
    [InlineData("1", "~1.1")]
    [InlineData("1.x", "~1.1.x")]
    [InlineData("~", "~1.~")]
    [InlineData("~x", "~1.~x")]
    [InlineData("~.x", "~1.~.x")]
    [InlineData("~1", "~1.~1")]
    [InlineData("~1.x", "~2.x")]
    [InlineData("~11.x", "~12.x")]
    [InlineData("~1.xx", "~2.xx")]
    [InlineData("~11.xx", "~12.xx")]
    [InlineData("~1.x.x", "~2.x.x")]
    [InlineData("~1.x~1.x", "~2.x~1.x")]
    public void Create_should_return_markedFile_with_valid_name_from_fileName_and_next_retryCount(string fileName, string expected)
    {
        // Arrange
        var markedFile = MarkedFile.Create(fileName);

        // Act & Assert
        Assert.Equal(expected, markedFile.Name);
    }

    [Fact]
    public void ToString_should_return_name()
    {
        // Arrange
        var markedFile = MarkedFile.Create("x");

        // Act & Assert
        Assert.Equal("~1.x", markedFile.Name);
    }
}
