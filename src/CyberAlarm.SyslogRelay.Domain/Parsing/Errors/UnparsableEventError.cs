using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Parsing.Errors;

internal sealed class UnparsableEventError(string message = "Failed to parse event.") : Error(message)
{
    public UnparsableEventError(IEnumerable<KeyValuePair<string, object>> metadata)
        : this()
    {
        foreach (var (key, value) in metadata)
        {
            Metadata.TryAdd(key, value);
        }
    }
}
