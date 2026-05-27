using System.Text.Json.Serialization;

namespace CyberAlarm.SyslogRelay.Common.Models;

public sealed record ParseResult(
    string SourceIp,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? DestinationIp,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? SourcePort,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? DestinationPort,
    EventProtocol Protocol,
    EventAction Action,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] TimeSpan? Duration = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] long? Bytes = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] bool? IsSourceLocal = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] bool? IsDestinationLocal = null);
