using System.Text.Json.Serialization;

namespace CyberAlarm.SyslogRelay.Common.Models;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum EventAction
{
    Unknown,
    Allow,
    Deny,
}
