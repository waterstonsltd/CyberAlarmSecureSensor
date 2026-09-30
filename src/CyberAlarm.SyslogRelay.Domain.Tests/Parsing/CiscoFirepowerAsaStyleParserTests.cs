using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Parsing.Cisco;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Parsing;

public sealed class CiscoFirepowerAsaStyleParserTests
{
    private readonly CiscoFirepowerAsaStyleParser _unitUnderTest = new();

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Parse_should_throw_when_log_is_empty(string? log)
    {
        // Act & Assert
        Assert.ThrowsAny<ArgumentException>(() => _unitUnderTest.Parse(log!));
    }

    [Fact]
    public void Parse_should_fail_when_log_has_incorrect_format()
    {
        // Act
        var result = _unitUnderTest.Parse(Guid.NewGuid().ToString());

        // Assert
        Assert.True(result.IsFailed);
        Assert.Equal("Log format is invalid.", result.ErrorMessage);
    }

    [Theory]
    [InlineData("%FTD-0-000000: x")]
    [InlineData("%FTD-0-106001: x")]
    public void Parse_should_fail_when_log_cannot_be_parsed(string log)
    {
        // Act
        var result = _unitUnderTest.Parse(log);

        // Assert
        Assert.True(result.IsFailed);
        Assert.Equal("Failed to parse event.", result.ErrorMessage);
    }

    [Theory]
    [MemberData(nameof(TestLogs), MemberType = typeof(CiscoFirepowerAsaStyleParserTests))]
    public void Parse_should_succeed_when_log_has_correct_format(string log, ParseResult parseResult)
    {
        // Act
        var result = _unitUnderTest.Parse(log);

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal(parseResult, result.Value);
    }

    public static TheoryData<string, ParseResult> TestLogs =>
        new()
        {
            {
                "<166>Apr 24 2026 13:45:44: %FTD-6-302013: Built inbound TCP connection 350490047 for admin:10.80.51.225/50823 (10.80.51.225/50823) to outside:54.194.25.164/443 (54.194.25.164/443)",
                new("10.80.51.225", "54.194.25.164", 50823, 443, EventProtocol.Tcp, EventAction.Allow)
            },
            {
                "<166>Apr 24 2026 13:45:44: %FTD-6-302014: Teardown TCP connection 350490040 for admin:10.80.61.86/57201 to outside:54.194.25.164/443 duration 0:00:00 bytes 182 TCP FINs from outside",
                new("10.80.61.86", "54.194.25.164", 57201, 443, EventProtocol.Tcp, EventAction.Close, TimeSpan.Zero, 182)
            },
            {
                "<166>Apr 24 2026 13:45:44: %FTD-6-302015: Built inbound UDP connection 12345 for outside:8.8.8.8/53 (8.8.8.8/53) to admin:10.80.1.5/12345 (10.80.1.5/12345)",
                new("8.8.8.8", "10.80.1.5", 53, 12345, EventProtocol.Udp, EventAction.Allow)
            },
            {
                "<164>Apr 24 2026 13:45:44: %FTD-4-106023: Deny udp src admin:10.80.50.54/62931 dst outside:104.21.59.200/443 by access-group \"CSM_FW_ACL_\" [0x97aa021a, 0x0]",
                new("10.80.50.54", "104.21.59.200", 62931, 443, EventProtocol.Udp, EventAction.Deny)
            },
            {
                "%FTD-6-302013: Built inbound TCP connection 123 for outside:192.0.2.1/12345 (192.0.2.1/12345) to NP Identity Iface:10.0.1.50/443 (10.0.1.50/443)",
                new("192.0.2.1", "10.0.1.50", 12345, 443, EventProtocol.Tcp, EventAction.Allow)
            },
            {
                "<166>Apr 24 2026 14:05:44: %FTD-6-302020: Built inbound ICMP connection for faddr 10.80.50.211/3591 gaddr 143.47.255.117/0 laddr 143.47.255.117/0 type 8 code 0",
                new("10.80.50.211", "143.47.255.117", null, null, EventProtocol.Icmp, EventAction.Allow)
            },
            {
                "<166>Apr 24 2026 14:05:44: %FTD-6-302021: Teardown ICMP connection for faddr 10.80.50.211/3590 gaddr 143.47.255.117/0 laddr 143.47.255.117/0 type 8 code 0",
                new("10.80.50.211", "143.47.255.117", null, null, EventProtocol.Icmp, EventAction.Timeout)
            },
            // IPv6 link-local ICMP (the known failing case from production logs)
            {
                "<166>Apr 24 2026 14:09:19: %FTD-6-302020: Built inbound ICMP connection for faddr fe80::84d9:75ff:feac:9505/0 gaddr fe80::200:1ff:fe00:1/0 laddr fe80::200:1ff:fe00:1/0 type 135 code 0",
                new("fe80::84d9:75ff:feac:9505", "fe80::200:1ff:fe00:1", null, null, EventProtocol.Icmp, EventAction.Allow)
            },
            {
                "<166>Apr 24 2026 14:09:19: %FTD-6-302020: Built outbound ICMP connection for faddr fe80::84d9:75ff:feac:9505/0 gaddr fe80::200:1ff:fe00:1/0 laddr fe80::200:1ff:fe00:1/0 type 136 code 0",
                new("fe80::84d9:75ff:feac:9505", "fe80::200:1ff:fe00:1", null, null, EventProtocol.Icmp, EventAction.Allow)
            },
            {
                "<166>Apr 24 2026 14:09:19: %FTD-6-302021: Teardown ICMP connection for faddr fe80::84d9:75ff:feac:9505/0 gaddr fe80::200:1ff:fe00:1/0 laddr fe80::200:1ff:fe00:1/0 type 135 code 0",
                new("fe80::84d9:75ff:feac:9505", "fe80::200:1ff:fe00:1", null, null, EventProtocol.Icmp, EventAction.Timeout)
            },
            // IPv6 TCP (bracketed format)
            {
                "<166>Apr 24 2026 13:45:44: %FTD-6-302013: Built inbound TCP connection 123 for outside:[2001:db8::1]/12345 ([2001:db8::1]/12345) to inside:[2001:db8::2]/443 ([2001:db8::2]/443)",
                new("2001:db8::1", "2001:db8::2", 12345, 443, EventProtocol.Tcp, EventAction.Allow)
            },
            // IPv6 UDP teardown (bracketed format) — first_iface=outside and src_port(53)<dst_port(12345) triggers swap
            {
                "<166>Apr 24 2026 13:45:44: %FTD-6-302016: Teardown UDP connection 999 for outside:[2001:db8::1]/53 to inside:[2001:db8::2]/12345 duration 0:00:00 bytes 72",
                new("2001:db8::2", "2001:db8::1", 12345, 53, EventProtocol.Udp, EventAction.Timeout, TimeSpan.Zero, 72)
            },
        };
}
