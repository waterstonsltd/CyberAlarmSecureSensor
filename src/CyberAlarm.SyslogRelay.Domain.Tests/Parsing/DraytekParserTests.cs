using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Parsing.Draytek;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Parsing;

public sealed class DraytekParserTests
{
    private readonly DraytekParser _unitUnderTest = new();

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
    [MemberData(nameof(TestLogs), MemberType = typeof(DraytekParserTests))]
    public void Parse_should_succeed_for_valid_draytek_logs(string log, ParseResult expected)
    {
        var result = _unitUnderTest.Parse(log);

        Assert.True(result.IsSuccess);
        Assert.Equal(expected, result.Value);
    }

    public static TheoryData<string, ParseResult> TestLogs =>
        new()
        {
            // Pass UDP – LAN to WAN DNS
            {
                "<134>Feb 11 15:03:45 RTR-EXAMPLE_data: 1449bc220888:[FILTER][Pass][LAN/RT/VPN->WAN, 121:50:32    ][@S:R=13:1, 192.168.1.26:63515->203.0.113.4:53][UDP][HLen=20, TLen=66]",
                new("192.168.1.26", "203.0.113.4", 63515, 53, EventProtocol.Udp, EventAction.Allow)
            },
            // Pass TCP – LAN to WAN HTTPS
            {
                "<134>Feb 11 15:03:45 RTR-EXAMPLE_data: 1449bc220888:[FILTER][Pass][LAN/RT/VPN->WAN, 121:50:32    ][@S:R=13:1, 192.168.1.10:49261->203.0.113.98:443][TCP][HLen=20, TLen=52, Flag=S, Seq=3523763994, Ack=0, Win=65535]",
                new("192.168.1.10", "203.0.113.98", 49261, 443, EventProtocol.Tcp, EventAction.Allow)
            },
            // Pass UDP – WAN to LAN (inbound)
            {
                "<134>Feb 11 15:03:46 RTR-EXAMPLE_data: 1449bc220888:[FILTER][Pass][WAN->LAN/RT/VPN, 121:50:33    ][@S:R=13:1, 203.0.113.67:29715->198.51.100.75:123][UDP][HLen=20, TLen=36]",
                new("203.0.113.67", "198.51.100.75", 29715, 123, EventProtocol.Udp, EventAction.Allow)
            },
            // Pass TCP – WAN to LAN (inbound)
            {
                "<134>Feb 11 15:03:48 RTR-EXAMPLE_data: 1449bc220888:[FILTER][Pass][WAN->LAN/RT/VPN, 121:50:35    ][@S:R=13:1, 203.0.113.121:43417->198.51.100.75:7547][TCP][HLen=20, TLen=44, Flag=S, Seq=1236052928, Ack=0, Win=14600]",
                new("203.0.113.121", "198.51.100.75", 43417, 7547, EventProtocol.Tcp, EventAction.Allow)
            },
            // Pass ICMP – no ports
            {
                "<134>Feb 11 15:03:46 RTR-EXAMPLE_data: 1449bc220888:[FILTER][Pass][WAN->LAN/RT/VPN, 121:50:33    ][@S:R=13:1, 203.0.113.4->198.51.100.75][ICMP][HLen=20, TLen=92, Type=0, Code=0]",
                new("203.0.113.4", "198.51.100.75", null, null, EventProtocol.Icmp, EventAction.Allow)
            },
            // Block TCP – deny action
            {
                "<134>Feb 11 15:03:45 RTR-EXAMPLE_data: 1449bc220888:[FILTER][Block][LAN/RT/VPN->WAN, 121:50:32    ][@S:R=14:1, 192.168.1.99:55000->203.0.113.1:80][TCP][HLen=20, TLen=40, Flag=S, Seq=100000000, Ack=0, Win=65535]",
                new("192.168.1.99", "203.0.113.1", 55000, 80, EventProtocol.Tcp, EventAction.Deny)
            },
            // Drop UDP – drop action
            {
                "[FILTER][Drop][LAN/RT/VPN->WAN, 0:53:53 ][@S:R=6:1, 192.168.1.10:60475->203.0.113.4:53][UDP][HLen=20, TLen=56]",
                new("192.168.1.10", "203.0.113.4", 60475, 53, EventProtocol.Udp, EventAction.Drop)
            },
            // Pass PR 47 (GRE) – numeric protocol notation, no ports
            {
                "<134>Feb  6 00:51:55 RTR-EXAMPLE_data: 1449bc220888:[FILTER][Pass][WAN->LAN/RT/VPN, 13:22:55    ][@S:R=13:1, 203.0.113.34->198.51.100.75][PR 47][HLen=20, TLen=572]",
                new("203.0.113.34", "198.51.100.75", null, null, EventProtocol.Gre, EventAction.Allow)
            },
        };
}
