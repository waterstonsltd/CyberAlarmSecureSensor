using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Parsing.PfSense;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Parsing;

public sealed class PfSenseParserTests
{
    private readonly PfSenseParser _unitUnderTest = new();

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
    [MemberData(nameof(TestLogs), MemberType = typeof(PfSenseParserTests))]
    public void Parse_should_succeed_for_valid_pfsense_logs(string log, ParseResult expected)
    {
        var result = _unitUnderTest.Parse(log);

        Assert.True(result.IsSuccess);
        Assert.Equal(expected, result.Value);
    }

    public static TheoryData<string, ParseResult> TestLogs =>
        new()
        {
            // RFC 3164 – block TCP inbound
            {
                "<134>Feb 10 22:26:53 filterlog[13075]: 8,,,1000000103,bce0,match,block,in,4,0x0,,47,10164,0,none,6,tcp,52,203.0.113.26,198.51.100.132,54836,12295,0,S,3232880658,,65535,,mss;nop;wscale;nop;nop;sackOK",
                new("203.0.113.26", "198.51.100.132", 54836, 12295, EventProtocol.Tcp, EventAction.Drop)
            },
            // RFC 5424 – pass TCP outbound
            {
                "<134>1 2026-02-11T08:11:51.915594+00:00 fw.example.com filterlog 49670 - - 2,51,,1000007911,pppoe2,match,pass,out,4,0x0,,63,45584,0,DF,6,tcp,60,198.51.100.14,203.0.113.193,41161,443,0,S,1110168407,,64240,,mss;sackOK;TS;nop;wscale",
                new("198.51.100.14", "203.0.113.193", 41161, 443, EventProtocol.Tcp, EventAction.Allow)
            },
            // RFC 5424 – pass UDP outbound DNS
            {
                "<134>1 2026-02-11T08:11:48.915571+00:00 fw.example.com filterlog 49670 - - 2,50,,1000007813,bge1,match,pass,out,4,0xa0,,62,0,0,DF,17,udp,51,10.131.1.1,10.132.0.100,58402,53,31",
                new("10.131.1.1", "10.132.0.100", 58402, 53, EventProtocol.Udp, EventAction.Allow)
            },
            // RFC 5424 – pass ICMP outbound (no ports)
            {
                "<134>1 2026-02-11T07:53:16.866007+00:00 fw.example.com filterlog 49670 - - 2,50,,1000007813,bge1,match,pass,out,4,0x0,,62,5705,0,DF,1,icmp,84,10.131.1.24,10.132.0.100,request,56026,2526864",
                new("10.131.1.24", "10.132.0.100", null, null, EventProtocol.Icmp, EventAction.Allow)
            },
            // RFC 5424 – block ICMP inbound (no ports)
            {
                "<134>1 2026-02-11T08:11:53.000000+00:00 fw.example.com filterlog 49670 - - 1,10,,1000000103,pppoe2,match,block,in,4,0x0,,60,11313,0,DF,1,icmp,188,203.0.113.155,10.132.0.102,request,35846,1846168",
                new("203.0.113.155", "10.132.0.102", null, null, EventProtocol.Icmp, EventAction.Drop)
            },
            // RFC 5424 – block TCP inbound
            {
                "<134>1 2026-02-11T08:11:48.915378+00:00 fw.example.com filterlog 49670 - - 1,10,,1000000103,pppoe2,match,block,in,4,0x0,,55,38704,0,none,6,tcp,60,203.0.113.128,10.132.0.106,19795,29789,0,S,755452409,,42340,,mss;sackOK;TS;nop;wscale",
                new("203.0.113.128", "10.132.0.106", 19795, 29789, EventProtocol.Tcp, EventAction.Drop)
            },
            // RFC 3164 – block IPv6 ICMPv6 (no ports)
            {
                "<134>Feb 10 22:27:13 filterlog[13075]: 4,,,1000000003,bce1,match,block,in,6,0x00,0x00000,255,ICMPv6,58,32,fe80::1,ff02::1,",
                new("fe80::1", "ff02::1", null, null, EventProtocol.Icmpv6, EventAction.Drop)
            },
            // reject action – maps to Deny (active response: TCP RST / ICMP unreachable)
            {
                "<134>Feb 10 22:30:00 filterlog[13075]: 5,,,1000000104,bce0,match,reject,in,4,0x0,,64,12345,0,DF,6,tcp,52,192.168.1.50,10.0.0.1,55123,80,0,S,123456789,,65535,,mss",
                new("192.168.1.50", "10.0.0.1", 55123, 80, EventProtocol.Tcp, EventAction.Deny)
            },
            // BSD format without PID (Netgate documentation format)
            {
                "Aug  3 08:59:02 master filterlog: 5,16777216,,1000000103,igb1,match,block,in,4,0x10,,128,0,0,none,17,udp,328,198.51.100.1,198.51.100.2,67,68,308",
                new("198.51.100.1", "198.51.100.2", 67, 68, EventProtocol.Udp, EventAction.Drop)
            },
        };
}
