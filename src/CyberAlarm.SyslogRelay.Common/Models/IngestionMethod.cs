using System.Text.Json.Serialization;

namespace CyberAlarm.SyslogRelay.Common.Models;

[JsonConverter(typeof(JsonStringEnumConverter<IngestionMethod>))]
public enum IngestionMethod
{
    Udp,
    Tcp,
    Tls,
    File,
}
