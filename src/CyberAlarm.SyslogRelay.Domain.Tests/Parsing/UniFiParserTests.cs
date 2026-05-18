using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Parsing.UniFi;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Parsing;

public sealed class UniFiParserTests
{
    private readonly UniFiParser _unitUnderTest = new();

    /// Canonical config matching the deployed pattern config for UniFi.
    /// DST is required (the pattern's ContainsAll rule guarantees SRC= and DST= are present).
    /// SPT/DPT are optional (absent for ICMP traffic).
    private static ParserConfig Config => new ParserConfigBuilder()
        .WithSourceIpKeys("SRC")
        .WithDestinationIpKeys("DST")
        .WithSourcePortKeys("SPT")
        .WithDestinationPortKeys("DPT")
        .WithProtocolKeys("PROTO")
        .WithActionValues(["A", "DNAT"], ["D"])
        .WithOptional(destinationIp: false, sourcePort: true, destinationPort: true, protocol: false)
        .Build();

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Parse_should_throw_when_log_is_empty(string? log)
    {
        _unitUnderTest.Initialise(Config);

        Assert.ThrowsAny<ArgumentException>(() => _unitUnderTest.Parse(log!));
    }

    [Theory]
    [InlineData("SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP SPT=1234 DPT=443")]
    [InlineData("<13>Mar 30 15:54:03 Cloud-Gateway-Fiber DESCR=\"no brackets\" SRC=1.2.3.4 DST=5.6.7.8")]
    public void Parse_should_fail_when_log_has_no_rule_chain_bracket(string log)
    {
        _unitUnderTest.Initialise(Config);

        var result = _unitUnderTest.Parse(log);

        Assert.True(result.IsFailed);
        Assert.Equal("Log format is invalid.", result.ErrorMessage);
    }

    [Theory]
    [InlineData("<13>Mar 30 15:54:00 host [WAN_IN-D-100] IN=eth0 OUT= MAC=aa:bb SRC= DST=1.2.3.4 PROTO=TCP SPT=1 DPT=2")]
    [InlineData("<13>Mar 30 15:54:00 host [WAN_IN-D-100] IN=eth0 OUT= MAC=aa:bb SRC=1.2.3.4 DST= PROTO=TCP SPT=1 DPT=2")]
    public void Parse_should_fail_when_log_is_missing_required_ip_fields(string log)
    {
        _unitUnderTest.Initialise(Config);

        var result = _unitUnderTest.Parse(log);

        Assert.True(result.IsFailed);
        Assert.Equal("Failed to parse event.", result.ErrorMessage);
    }

    [Theory]
    [MemberData(nameof(TestLogs), MemberType = typeof(UniFiParserTests))]
    public void Parse_should_succeed_for_valid_unifi_logs(string log, ParseResult expected)
    {
        _unitUnderTest.Initialise(Config);

        var result = _unitUnderTest.Parse(log);

        Assert.True(result.IsSuccess);
        Assert.Equal(expected, result.Value);
    }

    public static TheoryData<string, ParseResult> TestLogs =>
        new()
        {
            // ICMP allow – standard CUSTOM1_LOCAL zone, no SPT / DPT
            {
                "<13>Mar 30 15:54:03 Cloud-Gateway-Fiber [CUSTOM1_LOCAL-A-2147483647] DESCR=\"[CUSTOM1_LOCAL]Allow All T\" IN=br60 OUT= MAC=1c:0b:8b:10:a9:8c:48:da:35:6f:cd:59:08:00 SRC=192.168.60.100 DST=192.168.60.1 LEN=84 TOS=00 PREC=0x00 TTL=64 ID=16182 DF PROTO=ICMP TYPE=8 CODE=0 ID=9963 SEQ=1 MARK=1a0000",
                new("192.168.60.100", "192.168.60.1", null, null, EventProtocol.Icmp, EventAction.Allow)
            },
            // TCP deny – CUSTOM1_WAN zone, with SPT / DPT
            {
                "<13>Mar 30 15:54:04 Cloud-Gateway-Fiber [CUSTOM1_WAN-D-10000] DESCR=\"Deny All\" IN=br60 OUT=ppp0 MAC=1c:0b:8b:10:a9:8c:48:da:35:6f:cd:59:08:00 SRC=192.168.60.100 DST=52.71.215.234 LEN=60 TOS=00 PREC=0x00 TTL=63 ID=1973 DF PROTO=TCP SPT=46920 DPT=443 SEQ=3859934709 ACK=0 WINDOW=64240 SYN URGP=0 MARK=1a0000",
                new("192.168.60.100", "52.71.215.234", 46920, 443, EventProtocol.Tcp, EventAction.Deny)
            },
            // UDP deny – DMZ_LOCAL zone
            {
                "<13>Mar 30 15:54:04 Cloud-Gateway-Fiber [DMZ_LOCAL-D-2147483647] DESCR=\"[DMZ_LOCAL]Block All Traffic\" IN=br30 OUT= MAC=45:00:00:20:c9:d3:40:00:01:11:2b:f5:c0:a8 SRC=192.168.30.1 DST=233.89.188.1 LEN=32 TOS=00 PREC=0x00 TTL=1 ID=51667 DF PROTO=UDP SPT=39343 DPT=10001 LEN=12 MARK=1a0000",
                new("192.168.30.1", "233.89.188.1", 39343, 10001, EventProtocol.Udp, EventAction.Deny)
            },
            // ICMP allow – broadcast destination, CUSTOM1_LOCAL zone
            {
                "<13>Mar 30 15:54:04 Cloud-Gateway-Fiber [CUSTOM1_LOCAL-A-2147483647] DESCR=\"[CUSTOM1_LOCAL]Allow All T\" IN=br60 OUT= MAC=45:00:00:20:f3:bf:40:00:01:11:e4:08:c0:a8 SRC=192.168.60.1 DST=255.255.255.255 LEN=32 TOS=00 PREC=0x00 TTL=64 ID=62808 DF PROTO=UDP SPT=55062 DPT=10001 LEN=12 MARK=1a0000",
                new("192.168.60.1", "255.255.255.255", 55062, 10001, EventProtocol.Udp, EventAction.Allow)
            },
            // TCP deny – DMZ_LOCAL zone, loopback destination
            {
                "<13>Mar 30 15:54:07 Cloud-Gateway-Fiber [DMZ_LOCAL-D-2147483647] DESCR=\"[DMZ_LOCAL]Block All Traffic\" IN=br50 OUT= MAC=1c:0b:8b:10:a9:8c:44:65:0d:ef:7b:38:08:00 SRC=192.168.50.206 DST=127.0.0.1 LEN=60 TOS=00 PREC=0x00 TTL=64 ID=33581 DF PROTO=TCP SPT=50798 DPT=20443 SEQ=1349504113 ACK=0 WINDOW=4380 SYN URGP=0 MARK=1a0000",
                new("192.168.50.206", "127.0.0.1", 50798, 20443, EventProtocol.Tcp, EventAction.Deny)
            },
            // ICMP allow – standard WAN_IN zone
            {
                "<13>Mar 30 15:54:06 Cloud-Gateway-Fiber [WAN_IN-A-100] SRC=203.0.113.1 DST=10.0.0.1 PROTO=ICMP TYPE=8 CODE=0",
                new("203.0.113.1", "10.0.0.1", null, null, EventProtocol.Icmp, EventAction.Allow)
            },
            // TCP deny – LAN_OUT zone
            {
                "<13>Mar 30 15:54:06 Cloud-Gateway-Fiber [LAN_OUT-D-200] SRC=10.0.0.5 DST=10.0.0.6 PROTO=TCP SPT=55000 DPT=22",
                new("10.0.0.5", "10.0.0.6", 55000, 22, EventProtocol.Tcp, EventAction.Deny)
            },
            // ICMPv6 deny – IPv6 neighbour discovery blocked at DMZ boundary (no ports)
            {
                "<13>Mar 30 16:05:16 Cloud-Gateway-Fiber [DMZ_LOCAL-D-2147483647] DESCR=\"[DMZ_LOCAL]Block All Traffic\" IN=br30 OUT= MAC=1c:0b:8b:10:a9:8c:52:1c:bf:b7:9c:73:86:dd SRC=fe80::cac:63f4:ac07:aaab DST=fe80::1e0b:8bff:fe10:a98c LEN=84 TC=0 HOPLIMIT=255 FLOWLBL=396288 PROTO=UDP SPT=5353 DPT=5353 LEN=44 MARK=1a0000",
                new("fe80::cac:63f4:ac07:aaab", "fe80::1e0b:8bff:fe10:a98c", 5353, 5353, EventProtocol.Udp, EventAction.Deny)
            },
            // ICMPv6 deny – pure ICMPv6, no ports
            {
                "<13>Mar 30 16:05:16 Cloud-Gateway-Fiber [WAN_IN-D-100] IN=ppp0 OUT=br0 SRC=2001:db8::1 DST=2001:db8::2 PROTO=ICMPv6 TYPE=135 CODE=0",
                new("2001:db8::1", "2001:db8::2", null, null, EventProtocol.Icmpv6, EventAction.Deny)
            },
            // GRE deny – VPN tunnel traffic blocked
            {
                "<13>Mar 30 16:05:16 Cloud-Gateway-Fiber [WAN_IN-D-100] IN=ppp0 OUT=br0 SRC=203.0.113.5 DST=192.168.1.1 PROTO=GRE",
                new("203.0.113.5", "192.168.1.1", null, null, EventProtocol.Gre, EventAction.Deny)
            },
            // ESP deny – IPsec traffic blocked
            {
                "<13>Mar 30 16:05:16 Cloud-Gateway-Fiber [WAN_IN-D-100] IN=ppp0 OUT=br0 SRC=203.0.113.6 DST=192.168.1.1 PROTO=ESP",
                new("203.0.113.6", "192.168.1.1", null, null, EventProtocol.Esp, EventAction.Deny)
            },
            // TCP allow – PREROUTING-DNAT port-forward rule (inbound internet traffic forwarded to internal host)
            {
                "<13>May 15 16:48:53 Cloud-Gateway-Fiber [PREROUTING-DNAT-5] DESCR=\"PortForward DNAT [https]\" IN=ppp0 OUT= MAC=45:00:00:3c:f1:2c:40:00:3a:06:84:b1:a0:4f:6a:25:54:5c:6c:0d:88:00:01:bb:dc:ce SRC=160.79.106.37 DST=84.92.108.13 LEN=60 TOS=00 PREC=0x00 TTL=58 ID=61740 DF PROTO=TCP SPT=34816 DPT=443 SEQ=3704489390 ACK=0 WINDOW=35424 SYN URGP=0 MARK=1a0000",
                new("160.79.106.37", "84.92.108.13", 34816, 443, EventProtocol.Tcp, EventAction.Allow)
            },
        };
}
