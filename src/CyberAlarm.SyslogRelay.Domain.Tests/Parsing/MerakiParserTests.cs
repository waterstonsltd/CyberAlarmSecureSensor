using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Parsing.Meraki;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Parsing;

public sealed class MerakiParserTests
{
    private readonly MerakiParser _unitUnderTest = new();

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
    [MemberData(nameof(TestLogs), MemberType = typeof(MerakiParserTests))]
    public void Parse_should_succeed_for_valid_meraki_logs(string log, ParseResult expected)
    {
        var result = _unitUnderTest.Parse(log);

        Assert.True(result.IsSuccess);
        Assert.Equal(expected, result.Value);
    }

    public static TheoryData<string, ParseResult> TestLogs =>
        new()
        {
            {
                "<134>1 1776961789.089963919 06_I_FIREWALL_001 ip_flow_end src=10.206.2.7 dst=8.8.8.8 protocol=udp sport=47402 dport=53 translated_src_ip=194.73.206.226 translated_port=28969",
                new("10.206.2.7", "8.8.8.8", 47402, 53, EventProtocol.Udp, EventAction.Allow)
            },
            {
                "<134>1 1776962148.800408125 06_I_FIREWALL_001 ip_flow_end src=43.203.175.72 dst=194.73.206.226 protocol=icmp translated_dst_ip=194.73.206.226",
                new("43.203.175.72", "194.73.206.226", null, null, EventProtocol.Icmp, EventAction.Allow)
            },
            {
                "948077334.886213117 MX60 flows src=39.41.10.1 dst=114.18.20.30 protocol=udp sport=13943 dport=16329 pattern: 1 all",
                new("39.41.10.1", "114.18.20.30", 13943, 16329, EventProtocol.Udp, EventAction.Deny)
            },
            {
                "948136486.721741837 MX60 flows src=192.168.10.254 dst=8.8.8.8 mac=00:18:0A:AA:BB:CC protocol=udp sport=9562 dport=53 pattern: allow all",
                new("192.168.10.254", "8.8.8.8", 9562, 53, EventProtocol.Udp, EventAction.Allow)
            },
            {
                "<134>1 1776962148.151367883 07_I_FIREWALL_001 firewall src=45.142.193.9 dst=157.125.220.190 protocol=tcp sport=58412 dport=6027 pattern: 1 all",
                new("45.142.193.9", "157.125.220.190", 58412, 6027, EventProtocol.Tcp, EventAction.Deny)
            },
            {
                "<134>1 1776961789.018459260 06_I_FIREWALL_001 vpn_firewall src=10.203.18.230 dst=10.206.10.8 protocol=tcp sport=64806 dport=9264 pattern: allow all",
                new("10.203.18.230", "10.206.10.8", 64806, 9264, EventProtocol.Tcp, EventAction.Allow)
            },
            {
                "948136486.721741837 MX75 cellular_firewall src=192.168.20.10 dst=8.8.4.4 protocol=udp sport=60000 dport=53 pattern: deny all",
                new("192.168.20.10", "8.8.4.4", 60000, 53, EventProtocol.Udp, EventAction.Deny)
            },
            {
                "948136486.721741837 MX95 bridge_anyconnect_client_vpn_firewall src=10.0.0.10 dst=10.0.1.20 protocol=tcp sport=52345 dport=443 pattern: 0 all",
                new("10.0.0.10", "10.0.1.20", 52345, 443, EventProtocol.Tcp, EventAction.Allow)
            },
            {
                "<134>1 1776961795.106109599 10_I_FIREWALL_001 firewall src=fe80::280:91ff:fed1:35fc dst=ff02::1:2 protocol=udp sport=546 dport=547 pattern: 1 all",
                new("fe80::280:91ff:fed1:35fc", "ff02::1:2", 546, 547, EventProtocol.Udp, EventAction.Deny)
            },
            {
                "948136486.721741837 MX75 firewall src=203.0.113.10 dst=198.51.100.20 protocol=icmp pattern: allow all",
                new("203.0.113.10", "198.51.100.20", null, null, EventProtocol.Icmp, EventAction.Allow)
            },
            {
                "948136486.721741837 MX75 firewall src=203.0.113.10 dst=198.51.100.20 protocol=tcp sport=54321 dport=443",
                new("203.0.113.10", "198.51.100.20", 54321, 443, EventProtocol.Tcp, EventAction.Unknown)
            },
            // BSD syslog (RFC 3164) format — syslog server prepends MMM DD HH:MM:SS HOSTNAME before Meraki content
            {
                "<134>May  8 15:35:43 31.121.182.162 1 1778254543.885426267 01_I_FIREWALL_001 ip_flow_start src=10.201.67.246 dst=3.10.89.14 protocol=udp sport=53754 dport=53 translated_src_ip=31.121.182.162 translated_port=53754",
                new("10.201.67.246", "3.10.89.14", 53754, 53, EventProtocol.Udp, EventAction.Allow)
            },
            {
                "<134>May  8 15:35:45 31.121.182.162 1 1778254545.032772221 01_I_FIREWALL_001 ip_flow_end src=10.201.10.22 dst=13.107.138.10 protocol=tcp sport=60055 dport=443 translated_src_ip=31.121.182.162 translated_port=24539",
                new("10.201.10.22", "13.107.138.10", 60055, 443, EventProtocol.Tcp, EventAction.Allow)
            },
            {
                "<134>May  8 15:35:45 31.121.182.162 1 1778254545.032745624 01_I_FIREWALL_001 firewall src=18.117.161.11 dst=31.121.182.162 protocol=icmp type=8 pattern: 0 icmp && (dst 31.121.182.162)",
                new("18.117.161.11", "31.121.182.162", null, null, EventProtocol.Icmp, EventAction.Allow)
            },
            {
                "<134>May  8 15:35:46 31.121.182.162 1 1778254546.941966275 01_I_FIREWALL_001 vpn_firewall src=10.202.19.194 dst=10.201.11.121 protocol=tcp sport=63026 dport=9264 pattern: allow all",
                new("10.202.19.194", "10.201.11.121", 63026, 9264, EventProtocol.Tcp, EventAction.Allow)
            },
        };
}