using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Parsing.Untangle;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Parsing;

public sealed class UntangleParserTests
{
    private readonly UntangleParser _unitUnderTest = new();

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Parse_should_throw_when_log_is_empty(string? log)
    {
        Assert.ThrowsAny<ArgumentException>(() => _unitUnderTest.Parse(log!));
    }

    [Fact]
    public void Parse_should_fail_when_log_has_no_json()
    {
        var result = _unitUnderTest.Parse("no json here");

        Assert.True(result.IsFailed);
        Assert.Equal("Log format is invalid.", result.ErrorMessage);
    }

    [Fact]
    public void Parse_should_fail_when_json_is_invalid()
    {
        var result = _unitUnderTest.Parse("<13>May 22 14:37:16 INFO uvm {invalid json}");

        Assert.True(result.IsFailed);
        Assert.Equal("Log format is invalid.", result.ErrorMessage);
    }

    [Fact]
    public void Parse_should_fail_when_CClientAddr_is_missing()
    {
        var result = _unitUnderTest.Parse("<13>May 22 14:37:16 INFO uvm {\"CServerAddr\":\"1.2.3.4\",\"class\":\"class com.untangle.uvm.app.SessionEvent\"}");

        Assert.True(result.IsFailed);
        Assert.Equal("Failed to parse event.", result.ErrorMessage);
    }

    [Theory]
    [MemberData(nameof(TestLogs), MemberType = typeof(UntangleParserTests))]
    public void Parse_should_succeed_for_valid_untangle_logs(string log, ParseResult expected)
    {
        var result = _unitUnderTest.Parse(log);

        Assert.True(result.IsSuccess);
        Assert.Equal(expected.SourceIp, result.Value.SourceIp);
        Assert.Equal(expected.DestinationIp, result.Value.DestinationIp);
        Assert.Equal(expected.SourcePort, result.Value.SourcePort);
        Assert.Equal(expected.DestinationPort, result.Value.DestinationPort);
        Assert.Equal(expected.Protocol, result.Value.Protocol);
        Assert.Equal(expected.Action, result.Value.Action);
        Assert.Equal(expected.Bytes, result.Value.Bytes);
    }

    public static TheoryData<string, ParseResult> TestLogs =>
        new()
        {
            // SessionEvent - standalone session with all fields
            {
                "<13>May 22 14:37:16 INFO  uvm-to-10.26.52.204 {\"entitled\":true,\"protocol\":6,\"CServerPort\":443,\"hostname\":\"10.26.52.65\",\"protocolName\":\"TCP\",\"localAddr\":\"10.26.52.65\",\"class\":\"class com.untangle.uvm.app.SessionEvent\",\"SServerAddr\":\"54.77.117.111\",\"remoteAddr\":\"54.77.117.111\",\"serverIntf\":4,\"CClientAddr\":\"10.26.52.65\",\"serverCountry\":\"IE\",\"SClientAddr\":\"192.168.1.11\",\"sessionId\":116520902714075,\"policyRuleId\":0,\"CClientPort\":53154,\"clientCountry\":\"XL\",\"timeStamp\":\"2026-05-22 14:37:16.41\",\"clientIntf\":2,\"SClientPort\":53154,\"policyId\":1,\"SServerPort\":443,\"bypassed\":false,\"CServerAddr\":\"54.77.117.111\",\"tagsString\":\"\"}",
                new("10.26.52.65", "54.77.117.111", 53154, 443, EventProtocol.Tcp, EventAction.Allow)
            },
            // SessionNatEvent - nested sessionEvent
            {
                "<13>May 22 14:37:16 INFO  uvm-to-10.26.52.204 {\"timeStamp\":\"2026-05-22 14:37:16.41\",\"SClientPort\":27319,\"SServerPort\":443,\"SClientAddr\":\"192.168.1.11\",\"class\":\"class com.untangle.uvm.app.SessionNatEvent\",\"SServerAddr\":\"54.77.117.111\",\"serverIntf\":4,\"sessionEvent\":{\"entitled\":true,\"protocol\":6,\"CServerPort\":443,\"hostname\":\"10.26.52.65\",\"protocolName\":\"TCP\",\"localAddr\":\"10.26.52.65\",\"SServerAddr\":\"54.77.117.111\",\"remoteAddr\":\"54.77.117.111\",\"serverIntf\":4,\"CClientAddr\":\"10.26.52.65\",\"serverCountry\":\"IE\",\"SClientAddr\":\"192.168.1.11\",\"sessionId\":116520902714075,\"policyRuleId\":0,\"CClientPort\":53154,\"clientCountry\":\"XL\",\"timeStamp\":\"2026-05-22 14:37:16.41\",\"clientIntf\":2,\"SClientPort\":27319,\"policyId\":1,\"SServerPort\":443,\"bypassed\":false,\"CServerAddr\":\"54.77.117.111\",\"tagsString\":\"\"}}",
                new("10.26.52.65", "54.77.117.111", 53154, 443, EventProtocol.Tcp, EventAction.Allow)
            },
            // SessionStatsEvent - nested sessionEvent with byte counters
            {
                "<13>May 22 14:37:16 INFO  uvm-to-10.26.52.204 {\"timeStamp\":\"2026-05-22 14:37:16.497\",\"s2pBytes\":6140,\"p2sBytes\":9025,\"endTime\":1779457036497,\"sessionId\":116520902708736,\"class\":\"class com.untangle.uvm.app.SessionStatsEvent\",\"sessionEvent\":{\"entitled\":true,\"protocol\":6,\"CServerPort\":443,\"hostname\":\"10.26.52.62\",\"protocolName\":\"TCP\",\"localAddr\":\"10.26.52.62\",\"SServerAddr\":\"142.250.140.95\",\"remoteAddr\":\"142.250.140.95\",\"serverIntf\":4,\"CClientAddr\":\"10.26.52.62\",\"serverCountry\":\"BE\",\"SClientAddr\":\"192.168.1.11\",\"sessionId\":116520902708736,\"policyRuleId\":0,\"CClientPort\":52289,\"clientCountry\":\"XL\",\"timeStamp\":\"2026-05-22 14:32:16.558\",\"clientIntf\":2,\"SClientPort\":16869,\"policyId\":1,\"SServerPort\":443,\"bypassed\":false,\"CServerAddr\":\"142.250.140.95\",\"tagsString\":\"\"},\"c2pBytes\":9025,\"p2cBytes\":6140}",
                new("10.26.52.62", "142.250.140.95", 52289, 443, EventProtocol.Tcp, EventAction.Allow, Bytes: 30330)
            },
            // HttpRequestEvent - nested sessionEvent
            {
                "<13>May 22 14:37:16 INFO  uvm-to-10.26.52.204 {\"timeStamp\":\"2026-05-22 14:37:16.485\",\"method\":\"GET\",\"requestId\":116520895464888,\"domain\":\"calendar.google.com\",\"host\":\"calendar.google.com\",\"contentLength\":0,\"requestUri\":\"/\",\"class\":\"class com.untangle.app.http.HttpRequestEvent\",\"sessionEvent\":{\"entitled\":true,\"protocol\":6,\"CServerPort\":443,\"hostname\":\"10.26.52.62\",\"protocolName\":\"TCP\",\"localAddr\":\"10.26.52.62\",\"SServerAddr\":\"142.250.129.138\",\"remoteAddr\":\"142.250.129.138\",\"serverIntf\":4,\"CClientAddr\":\"10.26.52.62\",\"serverCountry\":\"BE\",\"SClientAddr\":\"192.168.1.11\",\"sessionId\":116520902714074,\"policyRuleId\":0,\"CClientPort\":62183,\"clientCountry\":\"XL\",\"timeStamp\":\"2026-05-22 14:37:16.39\",\"clientIntf\":2,\"SClientPort\":25141,\"policyId\":1,\"SServerPort\":443,\"bypassed\":false,\"CServerAddr\":\"142.250.129.138\",\"tagsString\":\"\"}}",
                new("10.26.52.62", "142.250.129.138", 62183, 443, EventProtocol.Tcp, EventAction.Allow)
            },
            // ThreatPreventionHttpEvent - nested sessionEvent with blocked=false at root
            {
                "<13>May 22 14:37:16 INFO  uvm-to-10.26.52.204 {\"reason\":\"DEFAULT\",\"requestLine\":\"GET http://calendar.google.com/\",\"serverReputation\":96,\"sessionEvent\":{\"entitled\":true,\"protocol\":6,\"CServerPort\":443,\"hostname\":\"10.26.52.62\",\"protocolName\":\"TCP\",\"localAddr\":\"10.26.52.62\",\"SServerAddr\":\"142.250.129.138\",\"remoteAddr\":\"142.250.129.138\",\"serverIntf\":4,\"CClientAddr\":\"10.26.52.62\",\"serverCountry\":\"BE\",\"SClientAddr\":\"192.168.1.11\",\"sessionId\":116520902714074,\"policyRuleId\":0,\"CClientPort\":62183,\"clientCountry\":\"XL\",\"timeStamp\":\"2026-05-22 14:37:16.39\",\"clientIntf\":2,\"SClientPort\":25141,\"policyId\":1,\"SServerPort\":443,\"bypassed\":false,\"CServerAddr\":\"142.250.129.138\",\"tagsString\":\"\"},\"timeStamp\":\"2026-05-22 14:37:16.485\",\"flagged\":false,\"blocked\":false,\"clientCategories\":0,\"serverCategories\":0,\"ruleId\":0,\"class\":\"class com.untangle.app.threat_prevention.ThreatPreventionHttpEvent\",\"clientReputation\":0}",
                new("10.26.52.62", "142.250.129.138", 62183, 443, EventProtocol.Tcp, EventAction.Allow)
            },
            // WebFilterEvent - nested sessionEvent
            {
                "<13>May 22 14:37:16 INFO  uvm-to-10.26.52.204 {\"reason\":\"DEFAULT\",\"appName\":\"web_filter\",\"requestLine\":\"GET http://calendar.google.com/\",\"sessionEvent\":{\"entitled\":true,\"protocol\":6,\"CServerPort\":443,\"hostname\":\"10.26.52.62\",\"protocolName\":\"TCP\",\"localAddr\":\"10.26.52.62\",\"SServerAddr\":\"142.250.129.138\",\"remoteAddr\":\"142.250.129.138\",\"serverIntf\":4,\"CClientAddr\":\"10.26.52.62\",\"serverCountry\":\"BE\",\"SClientAddr\":\"192.168.1.11\",\"sessionId\":116520902714074,\"policyRuleId\":0,\"CClientPort\":62183,\"clientCountry\":\"XL\",\"timeStamp\":\"2026-05-22 14:37:16.39\",\"clientIntf\":2,\"SClientPort\":25141,\"policyId\":1,\"SServerPort\":443,\"bypassed\":false,\"CServerAddr\":\"142.250.129.138\",\"tagsString\":\"\"},\"timeStamp\":\"2026-05-22 14:37:16.486\",\"flagged\":false,\"blocked\":false,\"category\":\"Search Engines\",\"ruleId\":50,\"class\":\"class com.untangle.app.web_filter.WebFilterEvent\",\"categoryId\":50}",
                new("10.26.52.62", "142.250.129.138", 62183, 443, EventProtocol.Tcp, EventAction.Allow)
            },
            // ApplicationControlLogEvent - nested sessionEvent
            {
                "<13>May 22 14:37:16 INFO  uvm-to-10.26.52.204 {\"protochain\":\"/TCP/SSL/HTTP2\",\"confidence\":100,\"sessionEvent\":{\"entitled\":true,\"protocol\":6,\"CServerPort\":443,\"hostname\":\"10.26.52.65\",\"protocolName\":\"TCP\",\"localAddr\":\"10.26.52.65\",\"SServerAddr\":\"54.77.117.111\",\"remoteAddr\":\"54.77.117.111\",\"serverIntf\":4,\"CClientAddr\":\"10.26.52.65\",\"serverCountry\":\"IE\",\"SClientAddr\":\"192.168.1.11\",\"sessionId\":116520902714075,\"policyRuleId\":0,\"CClientPort\":53154,\"clientCountry\":\"XL\",\"timeStamp\":\"2026-05-22 14:37:16.41\",\"clientIntf\":2,\"SClientPort\":27319,\"policyId\":1,\"SServerPort\":443,\"bypassed\":false,\"CServerAddr\":\"54.77.117.111\",\"tagsString\":\"\"},\"timeStamp\":\"2026-05-22 14:37:16.502\",\"application\":\"SSL\",\"flagged\":false,\"blocked\":false,\"detail\":\"4.sophosxl.net\",\"state\":3,\"category\":\"Web Services\",\"class\":\"class com.untangle.app.application_control.ApplicationControlLogEvent\"}",
                new("10.26.52.65", "54.77.117.111", 53154, 443, EventProtocol.Tcp, EventAction.Allow)
            },
            // UDP protocol
            {
                "<13>May 22 14:37:16 INFO  uvm {\"CClientAddr\":\"10.26.52.26\",\"CServerAddr\":\"8.8.8.8\",\"CClientPort\":49889,\"CServerPort\":53,\"protocolName\":\"UDP\",\"class\":\"class com.untangle.uvm.app.SessionEvent\"}",
                new("10.26.52.26", "8.8.8.8", 49889, 53, EventProtocol.Udp, EventAction.Allow)
            },
            // Blocked traffic (blocked=true)
            {
                "<13>May 22 14:37:16 INFO  uvm {\"blocked\":true,\"sessionEvent\":{\"CClientAddr\":\"192.168.1.100\",\"CServerAddr\":\"1.2.3.4\",\"CClientPort\":12345,\"CServerPort\":443,\"protocolName\":\"TCP\"},\"class\":\"class com.untangle.app.threat_prevention.ThreatPreventionHttpEvent\"}",
                new("192.168.1.100", "1.2.3.4", 12345, 443, EventProtocol.Tcp, EventAction.Deny)
            },
        };
}
