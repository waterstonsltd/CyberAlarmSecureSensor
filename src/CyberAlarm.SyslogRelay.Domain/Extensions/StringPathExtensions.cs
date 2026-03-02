namespace CyberAlarm.SyslogRelay.Domain.Extensions;

internal static class StringPathExtensions
{
    public static string? GetContainingFolder(this string path)
        => Path.GetDirectoryName(path)?
            .Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar)
            .Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries)
            .LastOrDefault();
}
