using System.Text.Json.Serialization;

namespace CyberAlarm.SyslogRelay.Common.Status.Models;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum RuleType
{
    StartsWith,
    EndsWith,
    ContainsAll,
    ContainsAny,
    MustNotContain,
    MinimumMatches,
    LengthRange,
}
