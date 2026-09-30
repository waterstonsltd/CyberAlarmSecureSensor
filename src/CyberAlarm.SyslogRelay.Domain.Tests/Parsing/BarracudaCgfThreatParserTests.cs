using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Parsing.Barracuda;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Parsing;

public sealed class BarracudaCgfThreatParserTests
{
    private readonly BarracudaCgfThreatParser _unitUnderTest = new();

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Parse_should_throw_when_log_is_empty(string? log)
    {
        Assert.ThrowsAny<ArgumentException>(() => _unitUnderTest.Parse(log!));
    }

    [Fact]
    public void Parse_should_fail_when_log_does_not_match_format()
    {
        var result = _unitUnderTest.Parse(Guid.NewGuid().ToString());

        Assert.True(result.IsFailed);
        Assert.Equal("Log format is invalid.", result.ErrorMessage);
    }

    [Theory]
    [MemberData(nameof(TestLogs), MemberType = typeof(BarracudaCgfThreatParserTests))]
    public void Parse_should_succeed_for_valid_barracuda_cgf_threat_logs(string log, ParseResult expected)
    {
        var result = _unitUnderTest.Parse(log);

        Assert.True(result.IsSuccess);
        Assert.Equal(expected, result.Value);
    }

    public static TheoryData<string, ParseResult> TestLogs =>
        new()
        {
            // IPS Allow — destination 0.0.0.0:0 normalised to null/null (scan detection, traffic permitted)
            {
                "<12>Feb 12 15:10:41 T100 T100/box_Firewall_threat:  Warning  T100 firewall: [Request] Allow:   IPS ALLIP(0) 10.0.0.22 -> 0.0.0.0:0 |[ID: 5000002 TCPIP Port or IP Address Scan]||3|Probing",
                new("10.0.0.22", null, null, null, EventProtocol.Unknown, EventAction.Allow)
            },
            // IPS Block — destination IP and port present, destination normalised
            {
                "<12>Feb 12 15:10:41 T100 T100/box_Firewall_threat:  Warning  T100 firewall: [Request] Block:   IPS ALLIP(0) 203.0.113.45 -> 10.0.0.254:22 |[ID: 5000001 SSH Brute Force]||3|Probing",
                new("203.0.113.45", "10.0.0.254", null, 22, EventProtocol.Unknown, EventAction.Deny)
            },
            // IPS Allow — known destination IP and non-zero port
            {
                "<12>Feb 12 15:10:41 T100 T100/box_Firewall_threat:  Warning  T100 firewall: [Request] Allow:   IPS ALLIP(0) 10.0.0.22 -> 203.0.113.1:443 |[ID: 5000003 TLS Inspection]||1|Info",
                new("10.0.0.22", "203.0.113.1", null, 443, EventProtocol.Unknown, EventAction.Allow)
            },
        };
}
