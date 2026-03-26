using System.Text.Json.Serialization;

namespace CyberAlarm.SyslogRelay.Common.Models;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum EventAction
{
    /// <summary>Action could not be determined from the log message.</summary>
    Unknown,

    /// <summary>Traffic was explicitly permitted by policy (e.g. firewall allow rule, built connection).</summary>
    Allow,

    /// <summary>Traffic was explicitly rejected by policy before a connection was established (e.g. ACL deny). The firewall typically sends a TCP RST or ICMP unreachable back to the sender.</summary>
    Deny,

    /// <summary>Traffic was silently discarded before a connection was established (e.g. embryonic limit, rate limit, IDS drop). No response is sent to the sender.</summary>
    Drop,

    /// <summary>An established connection was torn down gracefully via TCP FIN exchange — both sides agreed to close.</summary>
    Close,

    /// <summary>An established connection was forcibly terminated via TCP RST, or the firewall detected a protocol anomaly (e.g. segment out of order, invalid SYN) and reset the connection.</summary>
    Reset,

    /// <summary>An established connection was removed because it exceeded an idle or half-open timer (e.g. SYN timeout, connection timeout, no data). Also used for all UDP pseudo-connection teardowns.</summary>
    Timeout,
}
