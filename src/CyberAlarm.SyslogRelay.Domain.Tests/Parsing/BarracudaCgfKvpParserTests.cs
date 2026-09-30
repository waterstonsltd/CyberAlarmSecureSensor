using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Parsing.Barracuda;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Parsing;

public sealed class BarracudaCgfKvpParserTests
{
    private readonly BarracudaCgfKvpParser _unitUnderTest = new();

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
    [MemberData(nameof(TestLogs), MemberType = typeof(BarracudaCgfKvpParserTests))]
    public void Parse_should_succeed_for_valid_barracuda_cgf_kvp_logs(string log, ParseResult expected)
    {
        var result = _unitUnderTest.Parse(log);

        Assert.True(result.IsSuccess);
        Assert.Equal(expected, result.Value);
    }

    public static TheoryData<string, ParseResult> TestLogs =>
        new()
        {
            // Allow UDP — receivedBytes+sentBytes summed, duration=0
            {
                "<14>Feb 16 22:26:09 T100 T100/box_Firewall_Activity:  Info     T100 Allow: type=FWD|proto=UDP|srcIF=p1|srcIP=10.0.0.249|srcPort=42325|srcMAC=4c:cc:6a:2c:92:4e|dstIP=203.0.113.8|dstPort=53|dstService=dns|dstIF=p1|rule=LAN-2-INTERNET|info=Normal Operation|srcNAT=10.0.0.254|dstNAT=203.0.113.8|duration=0|count=1|receivedBytes=88|sentBytes=85|receivedPackets=1|sentPackets=1|user=|protocol=DNS|application=|target=|content=|urlcat=",
                new("10.0.0.249", "203.0.113.8", 42325, 53, EventProtocol.Udp, EventAction.Allow, TimeSpan.Zero, 173L)
            },
            // Block UDP → Drop — zero bytes
            {
                "<14>Feb 16 22:26:09 T100 T100/box_Firewall_Activity:  Info     T100 Block: type=FWD|proto=UDP|srcIF=p1|srcIP=203.0.113.50|srcPort=12345|srcMAC=4c:cc:6a:2c:92:4e|dstIP=10.0.0.254|dstPort=53|dstService=dns|dstIF=p1|rule=BLOCKALL|info=Normal Operation|srcNAT=203.0.113.50|dstNAT=10.0.0.254|duration=0|count=1|receivedBytes=0|sentBytes=0|receivedPackets=0|sentPackets=0|user=|protocol=|application=|target=|content=|urlcat=",
                new("203.0.113.50", "10.0.0.254", 12345, 53, EventProtocol.Udp, EventAction.Drop, TimeSpan.Zero, 0L)
            },
            // Detect UDP → Allow (application identification; traffic was forwarded)
            {
                "<14>Feb 16 22:26:09 T100 T100/box_Firewall_Activity:  Info     T100 Detect: type=FWD|proto=UDP|srcIF=p1|srcIP=10.0.0.249|srcPort=42325|srcMAC=4c:cc:6a:2c:92:4e|dstIP=203.0.113.8|dstPort=53|dstService=|dstIF=p1|rule=<APPPOL>:AppDefault|info=Normal Operation|srcNAT=10.0.0.254|dstNAT=203.0.113.8|duration=0|count=1|receivedBytes=0|sentBytes=0|receivedPackets=0|sentPackets=0|user=|protocol=DNS|application=|target=|content=|urlcat=",
                new("10.0.0.249", "203.0.113.8", 42325, 53, EventProtocol.Udp, EventAction.Allow, TimeSpan.Zero, 0L)
            },
            // Allow TCP — non-zero duration and bytes
            {
                "<14>Feb 16 22:26:09 T100 T100/box_Firewall_Activity:  Info     T100 Allow: type=FWD|proto=TCP|srcIF=p1|srcIP=10.0.0.22|srcPort=50000|srcMAC=c8:3a:35:b4:01:cc|dstIP=203.0.113.141|dstPort=443|dstService=https|dstIF=p1|rule=LAN-2-INTERNET|info=Normal Operation|srcNAT=10.0.0.254|dstNAT=203.0.113.141|duration=42|count=1|receivedBytes=1024|sentBytes=512|receivedPackets=8|sentPackets=4|user=|protocol=HTTPS|application=|target=|content=|urlcat=",
                new("10.0.0.22", "203.0.113.141", 50000, 443, EventProtocol.Tcp, EventAction.Allow, TimeSpan.FromSeconds(42), 1536L)
            },
            // Block IGMP(2) — Barracuda NAME(N) parenthesised protocol notation resolves via IANA number
            {
                "<9>Feb 16 21:37:50 T100 T100/box_Firewall_Activity:  Security T100 Block: type=FWD|proto=IGMP(2)|srcIF=p1|srcIP=10.0.0.1|srcPort=0|srcMAC=b8:8c:2b:2f:11:83|dstIP=224.0.0.1|dstPort=0|dstService=|dstIF=|rule=LAN-2-INTERNET|info=Block Multicast|srcNAT=|dstNAT=|duration=0|count=1|receivedBytes=0|sentBytes=0|receivedPackets=0|sentPackets=0|user=|protocol=|application=|target=|content=|urlcat=",
                new("10.0.0.1", "224.0.0.1", null, null, EventProtocol.Igmp, EventAction.Drop, TimeSpan.Zero, 0L)
            },
        };
}
