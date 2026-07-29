using System.Text.Json.Serialization;
using CyberAlarm.SyslogRelay.Common.EventBundler.Models;
using CyberAlarm.SyslogRelay.Common.Models;

namespace CyberAlarm.SyslogRelay.Domain;

[JsonSerializable(typeof(ParsedEvent))]
[JsonSerializable(typeof(BundleEvent))]
internal sealed partial class RelayJsonContext : JsonSerializerContext
{
}
