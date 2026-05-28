using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Parsing.WatchGuard;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Parsing;

public sealed class WatchGuardFireboxParserTests
{
    private readonly WatchGuardFireboxParser _unitUnderTest = new();

    private static WatchGuardParserConfig Config => new()
    {
        AllowActionValues = ["Allow"],
        DenyActionValues = ["Deny"],
        DurationKeys = ["duration"],
        DurationIsSeconds = true,
        SentBytesKeys = ["sent_bytes"],
        ReceivedBytesKeys = ["rcvd_bytes"],
    };

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Parse_should_throw_when_log_is_empty(string? log)
    {
        _unitUnderTest.Initialise(Config);

        Assert.ThrowsAny<ArgumentException>(() => _unitUnderTest.Parse(log!));
    }

    [Fact]
    public void Parse_should_fail_when_log_has_too_few_fields()
    {
        _unitUnderTest.Initialise(Config);

        var result = _unitUnderTest.Parse(Guid.NewGuid().ToString());

        Assert.True(result.IsFailed);
        Assert.Equal("Log format is invalid.", result.ErrorMessage);
    }

    [Theory]
    [MemberData(nameof(TestLogs), MemberType = typeof(WatchGuardFireboxParserTests))]
    public void Parse_should_succeed_for_valid_firebox_logs(string log, ParseResult expected)
    {
        _unitUnderTest.Initialise(Config);

        var result = _unitUnderTest.Parse(log);

        Assert.True(result.IsSuccess);
        Assert.Equal(expected, result.Value);
    }

    public static TheoryData<string, ParseResult> TestLogs =>
        new()
        {
            // Allow UDP – Firebox self-generated DNS traffic (with embedded timestamp)
            {
                @"<140>Feb 10 12:21:17 Firebox FCF117F354480 (2026-02-10T12:21:17) firewall: msg_id=""3000-0148"" Allow Firebox 2-External 91 udp 20 64 10.19.0.7 168.63.129.16 36803 53  (Any From Firebox-00)",
                new("10.19.0.7", "168.63.129.16", 36803, 53, EventProtocol.Udp, EventAction.Allow)
            },
            // Allow TCP – internal host to public HTTPS
            {
                @"<140>Feb 10 12:21:33 Firebox FCF117F354480 (2026-02-10T12:21:33) firewall: msg_id=""3000-0148"" Allow 1-Trusted 2-External 52 tcp 20 127 10.20.1.5 20.189.173.4 62671 443 offset 8 S 3674252099 win 65535  (HTTPS-00)",
                new("10.20.1.5", "20.189.173.4", 62671, 443, EventProtocol.Tcp, EventAction.Allow)
            },
            // Deny TCP – internal host to external HTTP
            {
                @"<140>Feb 10 12:21:23 Firebox FCF117F354480 (2026-02-10T12:21:23) firewall: msg_id=""3000-0148"" Deny 1-Trusted 2-External 52 tcp 20 127 10.20.1.5 85.234.74.60 62664 80 offset 8 S 182839930 win 65535  (Unhandled Internal Packet-00)",
                new("10.20.1.5", "85.234.74.60", 62664, 80, EventProtocol.Tcp, EventAction.Deny)
            },
            // Allow TCP – second internal host to HTTPS
            {
                @"<140>Feb 10 12:21:36 Firebox FCF117F354480 (2026-02-10T12:21:36) firewall: msg_id=""3000-0148"" Allow 1-Trusted 2-External 52 tcp 20 127 10.20.1.4 135.233.95.144 63845 443 offset 8 S 2010914860 win 65535  (HTTPS-00)",
                new("10.20.1.4", "135.233.95.144", 63845, 443, EventProtocol.Tcp, EventAction.Allow)
            },
            // Deny TCP – second internal host to external HTTP
            {
                @"<140>Feb 10 12:21:36 Firebox FCF117F354480 (2026-02-10T12:21:36) firewall: msg_id=""3000-0148"" Deny 1-Trusted 2-External 52 tcp 20 127 10.20.1.4 2.18.27.130 63846 80 offset 8 S 1541105412 win 65535  (Unhandled Internal Packet-00)",
                new("10.20.1.4", "2.18.27.130", 63846, 80, EventProtocol.Tcp, EventAction.Deny)
            },
            // Bug 1573: 3000-0151 short format (no pktLen/ttl/tos) with flags and duration
            // Note: Duration contains "128 seconds" which doesn't parse as pure number, so duration is null
            {
                @"<142>May 18 07:24:05 TestFirebox01 (2026-05-18T07:24:05) firewall: msg_id=""3000-0151"" Allow LAN BOVPN-WAN tcp 192.168.1.10 203.0.113.1 50397 443 flags=""SD"" duration=""128 seconds"" sent_pkts=""17"" rcvd_pkts=""15"" sent_bytes=""4233"" rcvd_bytes=""7474""  (Tunnel HTTP-S to BOVPN-00)",
                new("192.168.1.10", "203.0.113.1", 50397, 443, EventProtocol.Tcp, EventAction.Allow, null, 11707)
            },
            // Bug 1573: 3000-0148 standard format with flags
            {
                @"<140>May 17 03:59:04 TestFirebox01 (2026-05-17T03:59:04) firewall: msg_id=""3000-0148"" Deny LAN External 48 udp 20 126 192.168.1.11 203.0.113.2 65173 19302 flags=""SR"" duration=""0 seconds"" sent_pkts=""1"" rcvd_pkts=""0"" sent_bytes=""48"" rcvd_bytes=""0""  (Unhandled Internal Packet-00)",
                new("192.168.1.11", "203.0.113.2", 65173, 19302, EventProtocol.Udp, EventAction.Deny, null, 48)
            },
            // Bug 1573: 3000-0148 with fqdn_dst_match prefix
            {
                @"<140>May 17 03:59:04 TestFirebox01 (2026-05-17T03:59:04) firewall: msg_id=""3000-0148"" fqdn_dst_match=""example.com"" Allow LAN External 52 tcp 20 126 192.168.1.12 203.0.113.3 59935 443 offset 8 S 3834302385 win 65535  (HTTPS-00)",
                new("192.168.1.12", "203.0.113.3", 59935, 443, EventProtocol.Tcp, EventAction.Allow)
            },
            // Bug 1573: 3000-0151 ICMP format (no ports)
            {
                @"<142>May 17 03:59:04 TestFirebox01 (2026-05-17T03:59:04) firewall: msg_id=""3000-0151"" Allow Firebox External icmp 192.168.1.13 203.0.113.53 echo-request duration=""43 seconds"" sent_pkts=""1"" rcvd_pkts=""1"" sent_bytes=""84"" rcvd_bytes=""84""",
                new("192.168.1.13", "203.0.113.53", null, null, EventProtocol.Icmp, EventAction.Allow, null, 168)
            },
            // Bug 1573: TCP with offset fields before flags
            {
                @"<140>May 17 03:59:04 TestFirebox01 (2026-05-17T03:59:04) firewall: msg_id=""3000-0148"" Deny LAN External 48 tcp 20 62 192.168.1.14 203.0.113.4 664 8443 offset 7 S 2458163878 win 14370 flags=""SR"" duration=""0 seconds"" sent_pkts=""1"" rcvd_pkts=""0"" sent_bytes=""48"" rcvd_bytes=""0""  (Unhandled Internal Packet-00)",
                new("192.168.1.14", "203.0.113.4", 664, 8443, EventProtocol.Tcp, EventAction.Deny, null, 48)
            },
        };
}
