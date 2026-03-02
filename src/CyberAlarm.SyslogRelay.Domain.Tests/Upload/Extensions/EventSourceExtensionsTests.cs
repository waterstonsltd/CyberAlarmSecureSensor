using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Upload.Extensions;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Upload.Extensions;

public class EventSourceExtensionsTests
{
    [Theory]
    [InlineData(IngestionMethod.Tcp)]
    [InlineData(IngestionMethod.Udp)]
    public void NonFileSourceReturnsSourceWithoutModification(IngestionMethod ingestionMethod)
    {
        // Arrange
        var eventSource = new EventSource(ingestionMethod, "test.source");

        // Act
        var groupKey = eventSource.GetSanitisedGroupKey();

        // Assert
        Assert.Equal("test.source", groupKey);
    }

    [Theory]
    [InlineData("", "default")]
    [InlineData("root", "default")]
    [InlineData("abc", "abc")]
    public void FileSourceReturnsSanitisedSource(string source, string expected)
    {
        // Arrange
        var eventSource = new EventSource(IngestionMethod.File, source);

        // Act
        var groupKey = eventSource.GetSanitisedGroupKey();

        // Assert
        Assert.Equal(expected, groupKey);
    }

    [Theory]
    [InlineData('\0')]
    [InlineData('?')]
    [InlineData('*')]
    public void FileSourceRemovesInvalidPathCharacters(char invalidPathCharacter)
    {
        // Arrange
        var eventSource = new EventSource(IngestionMethod.File, $"PathWithInvalid{invalidPathCharacter}CharacterRemoved");

        // Act
        var groupKey = eventSource.GetSanitisedGroupKey();

        // Assert
        Assert.Equal("PathWithInvalidCharacterRemoved", groupKey);
    }
}
