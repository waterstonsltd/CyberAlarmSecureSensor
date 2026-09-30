using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Ingestion;

namespace CyberAlarm.SyslogRelay.Domain.Upload.Extensions;

public static class EventSourceExtensions
{
    public static string GetSanitisedGroupKey(this EventSource eventSource)
    {
        if (eventSource.IngestionMethod != IngestionMethod.File)
        {
            return eventSource.Source;
        }

        var sanitisedKey = Sanitise(eventSource.Source);

        if (string.IsNullOrEmpty(sanitisedKey) ||
            sanitisedKey == FileWatcher.RootSource)
        {
            return "default";
        }

        return sanitisedKey;
    }

    private static string Sanitise(string? path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return string.Empty;
        }

        var invalidChars = Path.GetInvalidPathChars()
            .Concat(Path.GetInvalidFileNameChars())
            .Concat(['.', '*', '?', Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar]);

        return new string([.. path.Where(ch => !invalidChars.Contains(ch))]);
    }
}
