using System.Text.Json.Serialization;

namespace CyberAlarm.SyslogRelay.Common.Models;

[JsonConverter(typeof(JsonStringEnumConverter<ValidationStatus>))]
public enum ValidationStatus
{
    Success,
    UnableToPatternMatch,
    UnableToParse,
    LocalOnlyEvent,
    OutboundEvent,
    Ignored,
}
