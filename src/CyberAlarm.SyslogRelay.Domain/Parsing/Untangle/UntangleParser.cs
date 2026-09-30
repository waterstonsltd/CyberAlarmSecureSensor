using System.Text.Json;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Parsing.Errors;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Parsing.Untangle;

/// <summary>
/// Parser for Untangle/Arista Edge Threat Management (ETM) syslog events.
/// Handles syslog-wrapped JSON events with various event classes, extracting
/// session data from either root-level fields or nested sessionEvent objects.
/// </summary>
internal sealed class UntangleParser : IParser
{
    public Result Initialise(object? config) => Result.Ok();

    public Result<ParseResult> Parse(string log)
    {
        ArgumentException.ThrowIfNullOrEmpty(log);

        var jsonStart = log.IndexOf('{');
        if (jsonStart < 0)
        {
            return new FormatError();
        }

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(log.AsMemory(jsonStart));
        }
        catch (JsonException)
        {
            return new FormatError();
        }

        using (doc)
        {
            var root = doc.RootElement;

            // Determine if session data is at root level or nested in sessionEvent
            var sessionElement = root.TryGetProperty("sessionEvent", out var nested)
                ? nested
                : root;

            // Extract required fields - CClientAddr/CServerAddr follow TCP client/server semantics
            if (!TryGetString(sessionElement, "CClientAddr", out var sourceIp) || string.IsNullOrEmpty(sourceIp))
            {
                return new UnparsableEventError();
            }

            TryGetString(sessionElement, "CServerAddr", out var destinationIp);
            var sourcePort = TryGetInt(sessionElement, "CClientPort");
            var destinationPort = TryGetInt(sessionElement, "CServerPort");

            TryGetString(sessionElement, "protocolName", out var protocolName);
            var protocol = protocolName.ToProtocol();

            // Determine action from blocked field (check both root and session for events like ThreatPreventionHttpEvent)
            var action = ResolveAction(root, sessionElement);

            // Extract bytes from SessionStatsEvent if available
            var bytes = ExtractBytes(root);

            return new ParseResult(
                sourceIp,
                destinationIp,
                sourcePort,
                destinationPort,
                protocol,
                action,
                Bytes: bytes);
        }
    }

    private static EventAction ResolveAction(JsonElement root, JsonElement sessionElement)
    {
        // Check root first (for events like ThreatPreventionHttpEvent that have blocked at root)
        if (root.TryGetProperty("blocked", out var rootBlocked) && rootBlocked.ValueKind == JsonValueKind.True)
        {
            return EventAction.Deny;
        }

        // Then check sessionEvent
        if (sessionElement.TryGetProperty("blocked", out var sessionBlocked) && sessionBlocked.ValueKind == JsonValueKind.True)
        {
            return EventAction.Deny;
        }

        // Default to Allow for established sessions
        return EventAction.Allow;
    }

    private static long? ExtractBytes(JsonElement root)
    {
        // SessionStatsEvent has byte counters: c2pBytes, p2cBytes (client to proxy, proxy to client)
        // or s2pBytes, p2sBytes (server to proxy, proxy to server)
        var c2p = TryGetLong(root, "c2pBytes");
        var p2c = TryGetLong(root, "p2cBytes");
        var s2p = TryGetLong(root, "s2pBytes");
        var p2s = TryGetLong(root, "p2sBytes");

        if (c2p.HasValue || p2c.HasValue || s2p.HasValue || p2s.HasValue)
        {
            return (c2p ?? 0) + (p2c ?? 0) + (s2p ?? 0) + (p2s ?? 0);
        }

        return null;
    }

    private static bool TryGetString(JsonElement element, string propertyName, out string? value)
    {
        if (element.TryGetProperty(propertyName, out var prop) && prop.ValueKind == JsonValueKind.String)
        {
            value = prop.GetString();
            return !string.IsNullOrEmpty(value);
        }

        value = null;
        return false;
    }

    private static int? TryGetInt(JsonElement element, string propertyName)
    {
        if (element.TryGetProperty(propertyName, out var prop) && prop.TryGetInt32(out var value))
        {
            return value;
        }

        return null;
    }

    private static long? TryGetLong(JsonElement element, string propertyName)
    {
        if (element.TryGetProperty(propertyName, out var prop) && prop.TryGetInt64(out var value))
        {
            return value;
        }

        return null;
    }
}
