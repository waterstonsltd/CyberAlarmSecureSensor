using System.Text.Json;
using CyberAlarm.SyslogRelay.Common.Models;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Ingestion;

internal static class RawExportTestData
{
    public const string Example = """{"Timestamp":"2026-09-14T20:20:50.6357315Z","RawData":"\u003C134\u003ESep 14 20:20:50 31.121.182.162 1 1789417250.629504682 01_I_FIREWALL_001 firewall src=54.155.108.25 dst=31.121.182.162 protocol=icmp type=8 pattern: 0 icmp \u0026\u0026 (dst 31.121.182.162)","PatternName":"Cisco Meraki","ParseResult":{"SourceIp":"54.155.108.25","DestinationIp":"31.121.182.162","Protocol":"Icmp","Action":"Allow","IsSourceLocal":false,"IsDestinationLocal":false},"ValidationStatus":"Success"}""";
    public const string Expected = "<134>Sep 14 20:20:50 31.121.182.162 1 1789417250.629504682 01_I_FIREWALL_001 firewall src=54.155.108.25 dst=31.121.182.162 protocol=icmp type=8 pattern: 0 icmp && (dst 31.121.182.162)";

    public static string Export(string raw) =>
        JsonSerializer.Serialize(new
        {
            Timestamp = "2020-01-01T00:00:00Z",
            RawData = raw,
            EventSource = new EventSource(IngestionMethod.Udp, "old-source"),
            PatternName = "Old parser",
            ParseResult = new { SourceIp = "obsolete" },
            ValidationStatus = "Success",
            DirectionDiagnostics = new { Reason = "Old decision" },
            FutureMetadata = "ignored",
        });
}
