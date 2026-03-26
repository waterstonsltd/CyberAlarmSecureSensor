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
}
