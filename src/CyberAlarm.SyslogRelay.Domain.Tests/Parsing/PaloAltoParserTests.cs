using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Parsing.PaloAlto;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Parsing;

public sealed class PaloAltoParserTests
{
    private readonly PaloAltoParser _unitUnderTest = new();

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
    [MemberData(nameof(TestLogs), MemberType = typeof(PaloAltoParserTests))]
    public void Parse_should_succeed_for_valid_paloalto_logs(string log, ParseResult expected)
    {
        var result = _unitUnderTest.Parse(log);

        Assert.True(result.IsSuccess);
        Assert.Equal(expected, result.Value);
    }

    public static TheoryData<string, ParseResult> TestLogs =>
        new()
        {
            // RFC 5424 with octet-count prefix – allow TCP outbound (real structure, sanitised IPs)
            {
                "716 <14>1 2026-01-27T07:57:08+00:00 fw.example.com - - - -  1,2026/01/27 07:57:03,TESTSERIAL,TRAFFIC,end,2818,2026/01/27 07:57:03,10.0.0.1,203.0.113.174,10.0.0.1,203.0.113.174,allow-internet,,,ssl,vsys1,Trust,untrust,eth1/1,eth1/2,Syslog-FWD,2026/01/27 07:57:08,617,1,50761,443,50761,443,0x40001c,tcp,allow,372,246,126,7,2026/01/27 07:56:49,18",
                new("10.0.0.1", "203.0.113.174", 50761, 443, EventProtocol.Tcp, EventAction.Allow, TimeSpan.FromSeconds(18), 372L)
            },
            // RFC 5424 without octet-count prefix – allow TCP outbound
            {
                "<14>1 2026-01-27T07:57:08+00:00 fw.example.com - - - -  1,2026/01/27 07:57:04,TESTSERIAL,TRAFFIC,end,2818,2026/01/27 07:57:04,10.0.0.2,203.0.113.80,10.0.0.2,203.0.113.80,allow-internet,,,ssl,vsys1,Trust,untrust,eth1/1,eth1/2,Syslog-FWD,2026/01/27 07:57:08,618,1,54329,80,54329,80,0x40001c,tcp,allow,432,246,186,7,2026/01/27 07:56:50,14",
                new("10.0.0.2", "203.0.113.80", 54329, 80, EventProtocol.Tcp, EventAction.Allow, TimeSpan.FromSeconds(14), 432L)
            },
            // Allow UDP (DNS) outbound
            {
                "<14>1 2026-01-27T08:00:00+00:00 fw.example.com - - - -  1,2026/01/27 08:00:00,TESTSERIAL,TRAFFIC,end,2818,2026/01/27 08:00:00,10.0.0.1,203.0.113.53,10.0.0.1,203.0.113.53,allow-internet,,,dns,vsys1,Trust,untrust,eth1/1,eth1/2,Syslog-FWD,2026/01/27 08:00:01,700,1,54000,53,54000,53,0x400010,udp,allow,173,88,85,2,2026/01/27 08:00:00,0",
                new("10.0.0.1", "203.0.113.53", 54000, 53, EventProtocol.Udp, EventAction.Allow, TimeSpan.Zero, 173L)
            },
            // Allow ICMP (ping) — no ports, subtype=end
            {
                "<14>1 2026-01-27T08:01:00+00:00 fw.example.com - - - -  1,2026/01/27 08:01:00,TESTSERIAL,TRAFFIC,end,2818,2026/01/27 08:01:00,10.0.0.1,203.0.113.1,10.0.0.1,203.0.113.1,allow-internet,,,ping,vsys1,Trust,untrust,eth1/1,eth1/2,Syslog-FWD,2026/01/27 08:01:02,800,1,8,0,8,0,0x0,icmp,allow,168,84,84,2,2026/01/27 08:01:00,2",
                new("10.0.0.1", "203.0.113.1", null, null, EventProtocol.Icmp, EventAction.Allow, TimeSpan.FromSeconds(2), 168L)
            },
            // Deny TCP inbound — active rejection (TCP RST / ICMP unreachable sent)
            {
                "<14>1 2026-01-27T08:02:00+00:00 fw.example.com - - - -  1,2026/01/27 08:02:00,TESTSERIAL,TRAFFIC,drop,2818,2026/01/27 08:02:00,198.51.100.50,10.0.0.10,198.51.100.50,10.0.0.10,block-inbound,,,not-applicable,vsys1,untrust,Trust,eth1/2,eth1/1,Syslog-FWD,2026/01/27 08:02:00,900,1,55000,22,55000,22,0x0,tcp,deny,60,60,0,1,2026/01/27 08:02:00,0",
                new("198.51.100.50", "10.0.0.10", 55000, 22, EventProtocol.Tcp, EventAction.Deny, TimeSpan.Zero, 60L)
            },
            // Drop TCP inbound — silent discard, no response sent
            {
                "<14>1 2026-01-27T08:03:00+00:00 fw.example.com - - - -  1,2026/01/27 08:03:00,TESTSERIAL,TRAFFIC,drop,2818,2026/01/27 08:03:00,198.51.100.100,10.0.0.10,198.51.100.100,10.0.0.10,block-inbound,,,not-applicable,vsys1,untrust,Trust,eth1/2,eth1/1,Syslog-FWD,2026/01/27 08:03:00,901,1,44444,8080,44444,8080,0x0,tcp,drop,0,0,0,0,2026/01/27 08:03:00,0",
                new("198.51.100.100", "10.0.0.10", 44444, 8080, EventProtocol.Tcp, EventAction.Drop, TimeSpan.Zero, 0L)
            },
            // THREAT vulnerability — reset-both maps to Deny; no bytes/duration extracted
            {
                "<14>1 2026-01-27T08:10:00+00:00 fw.example.com - - - -  1,2026/01/27 08:10:00,TESTSERIAL,THREAT,vulnerability,2818,2026/01/27 08:10:00,198.51.100.25,10.0.0.50,198.51.100.25,10.0.0.50,block-inbound,,,exploit,vsys1,untrust,Trust,eth1/2,eth1/1,Syslog-FWD,2026/01/27 08:10:00,999,1,44332,445,44332,445,0x0,tcp,reset-both,EternalBlue,41000,exploit,critical,server-to-client",
                new("198.51.100.25", "10.0.0.50", 44332, 445, EventProtocol.Tcp, EventAction.Deny)
            },
            // RFC 3164 (BSD-style syslog) — drop UDP inbound
            {
                "<14>Jun 12 11:20:05 fw.example.com 1,2026/06/12 11:20:04,TESTSERIAL,TRAFFIC,drop,2817,2026/06/12 11:20:04,198.51.100.27,203.0.113.232,0.0.0.0,0.0.0.0,block-inbound,,,not-applicable,vsys1,untrust,Trust,eth1/1,eth1/2,Syslog-FWD,2026/06/12 11:20:04,0,1,53067,500,0,0,0x0,udp,drop,394,394,0,1,2026/06/12 11:20:03,0",
                new("198.51.100.27", "203.0.113.232", 53067, 500, EventProtocol.Udp, EventAction.Drop, TimeSpan.Zero, 394L)
            },
            // RFC 3164 (BSD-style syslog) — allow TCP inbound
            {
                "<14>Jun 12 11:20:05 fw.example.com 1,2026/06/12 11:20:04,TESTSERIAL,TRAFFIC,end,2817,2026/06/12 11:20:04,198.51.100.134,203.0.113.128,198.51.100.134,10.0.0.153,allow-inbound,,,ssl,vsys1,untrust,Trust,eth1/1,eth1/2,Syslog-FWD,2026/06/12 11:20:04,33611718,1,22300,443,22300,443,0x40047a,tcp,allow,40733,8192,32541,106,2026/06/12 11:19:32,30",
                new("198.51.100.134", "203.0.113.128", 22300, 443, EventProtocol.Tcp, EventAction.Allow, TimeSpan.FromSeconds(30), 40733L)
            },
        };
}
