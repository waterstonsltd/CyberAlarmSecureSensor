using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Parsing.SonicWall;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Parsing;

public sealed class SonicWallParserTests
{
    private readonly SonicWallParser _unitUnderTest = new();

    private static SonicWallParserConfig Config => new()
    {
        AllowActionValues = ["allow"],
        DenyActionValues = ["deny", "block"],
        DropActionValues = ["drop"],
        ReceivedBytesKeys = ["rcvd"],
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
    public void Parse_should_fail_with_format_error_when_no_key_values()
    {
        _unitUnderTest.Initialise(Config);

        var result = _unitUnderTest.Parse(Guid.NewGuid().ToString());

        Assert.True(result.IsFailed);
        Assert.Equal("Log format is invalid.", result.ErrorMessage);
    }

    [Fact]
    public void Parse_should_succeed_for_port_scan_event()
    {
        _unitUnderTest.Initialise(Config);

        // IPs: 203.0.113.x = TEST-NET-3 (RFC 5737), 192.0.2.x = TEST-NET-1
        const string log = @"<129>  id=firewall sn=AABBCCDDEEFF time=""2001-01-01 09:00:00"" fw=192.0.2.1 pri=1 c=32 m=82 msg=""Possible port scan detected"" app=49369 appName='Service RPC Services (IANA)' n=2093 src=203.0.113.10:45099:X1 dst=192.0.2.1:56737:X1 srcMac=02:00:00:00:00:01 dstMac=02:00:00:00:00:02 proto=tcp/56737 note=""Pkt is dropped. TCP scanned port list, 19796, 997, 12367, 64030, 46152"" fw_action=""NA""";

        var result = _unitUnderTest.Parse(log);

        Assert.True(result.IsSuccess);
        var parsed = result.Value;
        Assert.Equal("203.0.113.10", parsed.SourceIp);
        Assert.Equal(45099, parsed.SourcePort);
        Assert.Equal("192.0.2.1", parsed.DestinationIp);
        Assert.Equal(56737, parsed.DestinationPort);
        Assert.Equal(EventProtocol.Tcp, parsed.Protocol);
        Assert.Equal(EventAction.Unknown, parsed.Action);
        Assert.Null(parsed.Bytes);
    }

    [Fact]
    public void Parse_should_succeed_for_dns_rebind_blocked_event()
    {
        _unitUnderTest.Initialise(Config);

        // IPs: 198.51.100.x = TEST-NET-2 (RFC 5737), 192.0.2.x = TEST-NET-1
        const string log = @"<129>  id=firewall sn=AABBCCDD1122 time=""2001-01-01 15:00:00"" fw=192.0.2.1 pri=1 c=0 gcat=6 m=1099 msg=""DNS rebind attack blocked"" srcMac=02:00:00:00:00:03 src=198.51.100.10:53:X1 srcZone=LAN natSrc=198.51.100.10:53 dstMac=02:00:00:00:00:04 dst=192.0.2.10:64519:X2 dstZone=WAN natDst=192.0.2.1:45192 usr=""testuser"" proto=udp/dns rcvd=84 sess=""Web"" rule=""Test Rule_1"" app=2 note=""FQDN=example.com; HOST=127.0.0.1"" n=1 fw_action=""drop""";

        var result = _unitUnderTest.Parse(log);

        Assert.True(result.IsSuccess);
        var parsed = result.Value;
        Assert.Equal("198.51.100.10", parsed.SourceIp);
        Assert.Equal(53, parsed.SourcePort);
        Assert.Equal("192.0.2.10", parsed.DestinationIp);
        Assert.Equal(64519, parsed.DestinationPort);
        Assert.Equal(EventProtocol.Udp, parsed.Protocol);
        Assert.Equal(EventAction.Drop, parsed.Action);
        Assert.Equal(84L, parsed.Bytes);
    }

    [Fact]
    public void Parse_should_fail_when_no_src_field_present()
    {
        _unitUnderTest.Initialise(Config);

        const string log = @"<129>  id=firewall sn=AABBCCDD1122 time=""2001-01-01 15:00:00"" fw=192.0.2.1 m=1099 msg=""Test event"" fw_action=""drop""";

        var result = _unitUnderTest.Parse(log);

        Assert.True(result.IsFailed);
        Assert.Equal("Failed to parse event.", result.ErrorMessage);
    }

    [Theory]
    [InlineData("proto=tcp/https", EventProtocol.Tcp)]
    [InlineData("proto=udp/dns", EventProtocol.Udp)]
    [InlineData("proto=icmp", EventProtocol.Icmp)]
    [InlineData("proto=tcp/56737", EventProtocol.Tcp)]
    public void Parse_should_resolve_protocol_correctly(string protoField, EventProtocol expected)
    {
        _unitUnderTest.Initialise(Config);

        var log = $@"<129>  id=firewall sn=AABBCCDD src=203.0.113.10:1234:X1 dst=192.0.2.1:80:X2 {protoField} fw_action=""drop""";

        var result = _unitUnderTest.Parse(log);

        Assert.True(result.IsSuccess);
        Assert.Equal(expected, result.Value.Protocol);
    }
}
