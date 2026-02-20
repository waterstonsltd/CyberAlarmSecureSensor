using System.Text.Json.Serialization;

namespace CyberAlarm.SyslogRelay.Common.Status.Models;

public sealed class PatternRule
{
    public RuleType Type { get; init; }

    public List<string> Values { get; init; } = [];

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? MinimumCount { get; init; }
}
