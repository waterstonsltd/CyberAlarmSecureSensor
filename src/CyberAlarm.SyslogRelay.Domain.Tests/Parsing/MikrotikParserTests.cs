using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Parsing.Mikrotik;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Parsing;

public sealed class MikrotikParserTests
{
    private readonly MikrotikParser _unitUnderTest = new();

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
    [MemberData(nameof(TestLogs), MemberType = typeof(MikrotikParserTests))]
    public void Parse_should_succeed_for_valid_mikrotik_logs(string log, ParseResult expected)
    {
        var result = _unitUnderTest.Parse(log);

        Assert.True(result.IsSuccess);
        Assert.Equal(expected, result.Value);
    }

    public static TheoryData<string, ParseResult> TestLogs =>
        new()
        {
            // TCP forward with NAT – pca-accept
            {
                "firewall,info pca-accept: pca-accept forward: in:Inspira Fibre Uplink out:3BEA VLAN, connection-state:established,snat src-mac 14:7b:ac:b3:3d:e6, proto TCP (ACK,PSH), 52.123.135.5:443->10.10.12.32:50849, NAT 52.123.135.5:443->(46.102.221.224:50849->10.10.12.32:50849), len 79",
                new("52.123.135.5", "10.10.12.32", 443, 50849, EventProtocol.Tcp, EventAction.Allow)
            },
            // TCP forward with NAT – pca-deny prefix (same traffic, deny disposition)
            {
                "firewall,info pca-deny: pca-accept forward: in:Inspira Fibre Uplink out:3BEA VLAN, connection-state:established,snat src-mac 14:7b:ac:b3:3d:e6, proto TCP (ACK,PSH), 52.123.135.5:443->10.10.12.32:50849, NAT 52.123.135.5:443->(46.102.221.224:50849->10.10.12.32:50849), len 79",
                new("52.123.135.5", "10.10.12.32", 443, 50849, EventProtocol.Tcp, EventAction.Deny)
            },
            // ICMP forward (no ports) – pca-accept
            {
                "firewall,info pca-accept: pca-accept forward: in:3BEA VLAN out:Inspira Fibre Uplink, connection-state:new src-mac 02:01:24:03:ed:66, proto ICMP (type 8, code 0), 10.10.12.30->157.240.214.35, len 76",
                new("10.10.12.30", "157.240.214.35", null, null, EventProtocol.Icmp, EventAction.Allow)
            },
            // ICMP forward (no ports) – pca-deny
            {
                "firewall,info pca-deny: pca-accept forward: in:3BEA VLAN out:Inspira Fibre Uplink, connection-state:new src-mac 02:01:24:03:ed:66, proto ICMP (type 8, code 0), 10.10.12.30->157.240.214.35, len 76",
                new("10.10.12.30", "157.240.214.35", null, null, EventProtocol.Icmp, EventAction.Deny)
            },
            // TCP outbound (LAN → WAN) with outbound SNAT – src should be the public external IP from NAT section
            {
                "firewall,info pca-accept: pca-accept forward: in:3BEA VLAN out:Inspira Fibre Uplink, connection-state:established,snat src-mac a8:7e:ea:33:f7:57, proto TCP (ACK), 10.10.12.32:50849->52.123.135.5:443, NAT (10.10.12.32:50849->46.102.221.224:50849)->52.123.135.5:443, len 40",
                new("46.102.221.224", "52.123.135.5", 50849, 443, EventProtocol.Tcp, EventAction.Allow)
            },
            // UDP input chain – pca-accept
            {
                "firewall,info pca-accept: PCA input: in:Inspira Fibre Uplink out:(unknown 0), connection-state:established src-mac 14:7b:ac:b3:3d:e6, proto UDP, 87.117.83.154:49295->46.102.221.224:13231, len 1276",
                new("87.117.83.154", "46.102.221.224", 49295, 13231, EventProtocol.Udp, EventAction.Allow)
            },
            // UDP input chain – pca-deny
            {
                "firewall,info pca-deny: PCA input: in:Inspira Fibre Uplink out:(unknown 0), connection-state:established src-mac 14:7b:ac:b3:3d:e6, proto UDP, 87.117.83.154:49295->46.102.221.224:13231, len 1276",
                new("87.117.83.154", "46.102.221.224", 49295, 13231, EventProtocol.Udp, EventAction.Deny)
            },
            // ICMP with SNAT and NAT section – pca-accept
            {
                "firewall,info pca-accept: pca-accept forward: in:Inspira Fibre Uplink out:3BEA VLAN, connection-state:related,snat src-mac 14:7b:ac:b3:3d:e6, proto ICMP (type 11, code 0), 188.240.160.85->10.10.12.30, NAT 157.240.214.35->(46.102.221.224->10.10.12.30), len 56",
                new("188.240.160.85", "10.10.12.30", null, null, EventProtocol.Icmp, EventAction.Allow)
            },
            // ICMP with outbound SNAT – src should be the public external IP, no ports
            {
                "firewall,info pca-accept: pca-accept forward: in:3BEA VLAN out:Inspira Fibre Uplink, connection-state:new,snat src-mac 02:01:24:03:ed:66, proto ICMP (type 8, code 0), 10.10.12.30->157.240.214.35, NAT (10.10.12.30->46.102.221.224)->157.240.214.35, len 76",
                new("46.102.221.224", "157.240.214.35", null, null, EventProtocol.Icmp, EventAction.Allow)
            },
            // TCP inbound with DNAT – "NAT src->(external->internal)" form should NOT override src
            {
                "firewall,info pca-accept: pca-accept forward: in:Inspira Fibre Uplink out:3BEA VLAN, connection-state:established,snat src-mac 14:7b:ac:b3:3d:e6, proto TCP (ACK,PSH), 52.123.135.5:443->10.10.12.32:50849, NAT 52.123.135.5:443->(46.102.221.224:50849->10.10.12.32:50849), len 79",
                new("52.123.135.5", "10.10.12.32", 443, 50849, EventProtocol.Tcp, EventAction.Allow)
            },
            // pca-drop prefix maps to Drop
            {
                "firewall,info pca-drop: pca-drop forward: in:ether1 out:ether2, connection-state:invalid src-mac aa:bb:cc:dd:ee:ff, proto TCP (SYN), 192.0.2.1:12345->10.0.0.1:80, len 60",
                new("192.0.2.1", "10.0.0.1", 12345, 80, EventProtocol.Tcp, EventAction.Drop)
            },
            // pca-reject prefix maps to Deny
            {
                "firewall,info pca-reject: pca-reject input: in:ether1 out:(unknown 0), connection-state:new src-mac aa:bb:cc:dd:ee:ff, proto TCP (SYN), 198.51.100.10:54321->203.0.113.1:22, len 60",
                new("198.51.100.10", "203.0.113.1", 54321, 22, EventProtocol.Tcp, EventAction.Deny)
            },
            // WireGuard VPN traffic – no src-mac present
            {
                "firewall,info pca-accept: pca-accept forward: in:wireguard1 out:Inspira Fibre Uplink, connection-state:established,snat proto TCP (ACK,PSH), 192.168.5.50:57922->52.123.139.72:443, NAT (192.168.5.50:57922->46.102.221.224:57922)->52.123.139.72:443, len 97",
                new("46.102.221.224", "52.123.139.72", 57922, 443, EventProtocol.Tcp, EventAction.Allow)
            },
        };
}
