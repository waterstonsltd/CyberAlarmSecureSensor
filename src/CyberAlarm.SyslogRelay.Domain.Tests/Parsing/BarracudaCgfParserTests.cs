using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Parsing.Barracuda;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Parsing;

public sealed class BarracudaCgfParserTests
{
    private readonly BarracudaCgfParser _unitUnderTest = new();

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
    [MemberData(nameof(TestLogs), MemberType = typeof(BarracudaCgfParserTests))]
    public void Parse_should_succeed_for_valid_barracuda_cgf_logs(string log, ParseResult expected)
    {
        var result = _unitUnderTest.Parse(log);

        Assert.True(result.IsSuccess);
        Assert.Equal(expected, result.Value);
    }

    public static TheoryData<string, ParseResult> TestLogs =>
        new()
        {
            // Allow TCP (IFWD — inbound-forwarded, LAN to WAN HTTPS)
            {
                "<14>Feb 12 15:40:09 T100 T100/box_Firewall_Activity:  Info     T100 Allow: IFWD|TCP|p1|10.0.0.22|58086|c8:3a:35:b4:01:cc|203.0.113.141|443|https|p1|LAN-2-INTERNET|0|10.0.0.254|203.0.113.141|18|1|0|0|0|0||||||",
                new("10.0.0.22", "203.0.113.141", 58086, 443, EventProtocol.Tcp, EventAction.Allow, TimeSpan.FromSeconds(18))
            },
            // Block TCP → Drop (FWD, inbound from internet, rule BLOCKALL)
            {
                "<9>Feb 12 15:40:10 T100 T100/box_Firewall_Activity:  Security T100 Block: FWD|TCP|p1|203.0.113.95|49959|b8:8c:2b:2f:11:83|10.0.0.254|25|smtp||BLOCKALL|4002|||0|1|0|0|0|0||||||",
                new("203.0.113.95", "10.0.0.254", 49959, 25, EventProtocol.Tcp, EventAction.Drop, TimeSpan.Zero)
            },
            // Allow UDP (FWD — forwarded, DNS)
            {
                "<14>Feb 12 16:14:01 T100 T100/box_Firewall_Activity:  Info     T100 Allow: FWD|UDP|p1|10.0.0.249|55018|4c:cc:6a:2c:92:4e|203.0.113.22|53|dns|p1|LAN-2-INTERNET|0|10.0.0.254|203.0.113.22|0|1|0|0|0|0||||||",
                new("10.0.0.249", "203.0.113.22", 55018, 53, EventProtocol.Udp, EventAction.Allow, TimeSpan.Zero)
            },
            // Allow ICMP — no ports extracted
            {
                "<14>Feb 12 16:13:56 T100 T100/box_Firewall_Activity:  Info     T100 Allow: FWD|ICMP|p1|10.0.0.249|13514|4c:cc:6a:2c:92:4e|203.0.113.1|13514||p1|LAN-2-INTERNET|0|10.0.0.254|203.0.113.1|2|1|0|0|0|0||||||",
                new("10.0.0.249", "203.0.113.1", null, null, EventProtocol.Icmp, EventAction.Allow, TimeSpan.FromSeconds(2))
            },
            // Detect TCP → Allow (application detection; traffic was forwarded)
            {
                "<14>Feb 16 22:26:09 T100 T100/box_Firewall_Activity:  Info     T100 Detect: IFWD|TCP|p1|10.0.0.22|50000|c8:3a:35:b4:01:cc|203.0.113.80|443|https|p1|LAN-2-INTERNET|0|10.0.0.254|203.0.113.80|5|1|0|0|0|0||||||",
                new("10.0.0.22", "203.0.113.80", 50000, 443, EventProtocol.Tcp, EventAction.Allow, TimeSpan.FromSeconds(5))
            },
            // Block IGMP(2) — Barracuda NAME(N) parenthesised protocol notation resolves via IANA number
            {
                "<9>Feb 12 16:08:37 T100 T100/box_Firewall_Activity:  Security T100 Block: FWD|IGMP(2)|p1|10.0.0.1|0|b8:8c:2b:2f:11:83|224.0.0.1|0|||LAN-2-INTERNET|4018|||0|1|0|0|0|0||||||",
                new("10.0.0.1", "224.0.0.1", null, null, EventProtocol.Igmp, EventAction.Drop, TimeSpan.Zero)
            },
        };
}
