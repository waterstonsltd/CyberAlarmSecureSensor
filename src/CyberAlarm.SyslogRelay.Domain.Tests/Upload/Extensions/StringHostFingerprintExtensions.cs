using CyberAlarm.SyslogRelay.Domain.Upload.Extensions;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Upload.Extensions;

public class StringHostFingerprintExtensions
{
    [Theory]
    [InlineData("abc123", "abc123", true)]
    [InlineData("abc123", "def456", false)]
    [InlineData("abc123", "abc123=", true)]
    [InlineData("abc123", "abc123==", true)]
    [InlineData("abc123", "", false)]
    [InlineData("", "abc123", false)]
    public void IndicatesMatchingHostFingerprints(string hostFingerprint, string otherHostFingerprint, bool expected)
    {
        var actual = hostFingerprint.MatchesHostFingerprint(otherHostFingerprint);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void MatchesAnyHostFingerprint_ReturnsTrueWhenPrimaryMatches()
    {
        var result = "abc123".MatchesAnyHostFingerprint(["abc123", "def456"]);

        Assert.True(result);
    }

    [Fact]
    public void MatchesAnyHostFingerprint_ReturnsTrueWhenSecondaryMatches()
    {
        var result = "def456".MatchesAnyHostFingerprint(["abc123", "def456"]);

        Assert.True(result);
    }

    [Fact]
    public void MatchesAnyHostFingerprint_ReturnsFalseWhenNoMatch()
    {
        var result = "xyz999".MatchesAnyHostFingerprint(["abc123", "def456"]);

        Assert.False(result);
    }

    [Fact]
    public void MatchesAnyHostFingerprint_ReturnsFalseForEmptyList()
    {
        var result = "abc123".MatchesAnyHostFingerprint([]);

        Assert.False(result);
    }

    [Fact]
    public void MatchesAnyHostFingerprint_HandlesPaddingNormalization()
    {
        var result = "abc123".MatchesAnyHostFingerprint(["abc123=="]);

        Assert.True(result);
    }
}
