namespace CyberAlarm.SyslogRelay.Domain.Upload.Extensions;

public static class StringHostFingerprintExtensions
{
    public static bool MatchesHostFingerprint(this string hostFingerprint, string otherHostFingerprint)
        => string.Equals(hostFingerprint.Normalized(), otherHostFingerprint.Normalized(), StringComparison.Ordinal);

    public static bool MatchesAnyHostFingerprint(this string received, IReadOnlyList<string> fingerprints)
        => fingerprints.Any(fp => received.MatchesHostFingerprint(fp));

    public static string Normalized(this string hostFingerprint)
        => hostFingerprint.TrimEnd('=');
}
