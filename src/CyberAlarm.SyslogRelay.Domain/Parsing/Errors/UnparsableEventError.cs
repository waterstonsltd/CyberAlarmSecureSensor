using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Parsing.Errors;

internal sealed class UnparsableEventError(string message) : Error(message)
{
    public UnparsableEventError(IEnumerable<KeyValuePair<string, object>> metadata)
        : this("Failed to parse event.")
    {
        foreach (var (key, value) in metadata)
        {
            Metadata.TryAdd(key, value);
        }
    }
}
