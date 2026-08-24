using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Parsing.LinuxNetfilter;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Parsing;

public sealed class LinuxNetfilterParserTests
{
    private readonly LinuxNetfilterParser _unitUnderTest = new();

    private static LinuxNetfilterParserConfig Config => new()
    {
        SourceIpKeys = ["SRC"],
        DestinationIpKeys = ["DST"],
        SourcePortKeys = ["SPT"],
        DestinationPortKeys = ["DPT"],
        ProtocolKeys = ["PROTO"],
        ActionKeys = [],
        IsDestinationIpOptional = false,
        IsSourcePortOptional = true,
        IsDestinationPortOptional = true,
        IsProtocolOptional = false,
        AllowActionValues = ["A", "NAT", "DNAT"],
        DenyActionValues = ["D"],
        ActionExtractRegex = @"\[[^\]\s]+-([A-Z]+)(?:-\d+)?\]",
    };

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
    [InlineData("<4>Aug 19 05:53:02 host kernel: no bracket SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP")]
    public void Parse_should_fail_when_log_has_no_matching_action_token(string log)
    {
        _unitUnderTest.Initialise(Config);

        var result = _unitUnderTest.Parse(log);

        Assert.True(result.IsFailed);
        Assert.Equal("Log format is invalid.", result.ErrorMessage);
    }

    [Theory]
    [InlineData("<4>Aug 19 05:53:02 host kernel: [ipv6-INP-filter-default-D]IN=vti0 OUT= SRC= DST=fc00::2 PROTO=TCP SPT=7250 DPT=8085")]
    [InlineData("<4>Aug 19 05:53:02 host kernel: [ipv6-INP-filter-default-D]IN=vti0 OUT= SRC=fc00::1 DST= PROTO=TCP SPT=7250 DPT=8085")]
    public void Parse_should_fail_when_log_is_missing_required_ip_fields(string log)
    {
        _unitUnderTest.Initialise(Config);

        var result = _unitUnderTest.Parse(log);

        Assert.True(result.IsFailed);
        Assert.Equal("Failed to parse event.", result.ErrorMessage);
    }

    [Theory]
    [MemberData(nameof(TestLogs), MemberType = typeof(LinuxNetfilterParserTests))]
    public void Parse_should_succeed_for_valid_linux_netfilter_logs(string log, ParseResult expected)
    {
        _unitUnderTest.Initialise(Config);

        var result = _unitUnderTest.Parse(log);

        Assert.True(result.IsSuccess);
        Assert.Equal(expected, result.Value);
    }

    public static TheoryData<string, ParseResult> TestLogs =>
        new()
        {
            {
                "<4>Aug 19 05:53:02 EXAHW00002B2F3 kernel: [ipv6-INP-filter-default-D]IN=vti0 OUT= MAC= SRC=fc00::1 DST=fc00::2 LEN=72 TC=0 HOPLIMIT=64 FLOWLBL=726340 PROTO=TCP SPT=7250 DPT=8085 WINDOW=42880 RES=0x00 SYN URGP=0",
                new("fc00::1", "fc00::2", 7250, 8085, EventProtocol.Tcp, EventAction.Deny)
            },
            {
                "<4>Aug 19 05:53:02 EXAHW00002B2F3 kernel: [ipv4-INP-filter-default-D]IN=vti0 OUT= SRC=172.17.1.2 DST=8.8.8.8 LEN=56 TOS=0x00 PREC=0x00 TTL=64 ID=57464 PROTO=UDP SPT=31135 DPT=53 LEN=36",
                new("172.17.1.2", "8.8.8.8", 31135, 53, EventProtocol.Udp, EventAction.Deny)
            },
            {
                "<4>Aug 18 13:18:01 EXAHW00002B2F3 kernel: [DST-NAT-1]IN=eth4 OUT= SRC=172.17.1.2 DST=8.8.8.8 LEN=56 TOS=0x00 PREC=0x00 TTL=64 ID=57464 PROTO=UDP SPT=31135 DPT=53 LEN=36",
                new("172.17.1.2", "8.8.8.8", 31135, 53, EventProtocol.Udp, EventAction.Allow)
            },
            {
                "<4>Aug 18 13:18:01 EXAHW00002B2F3 kernel: [ipv6-INP-filter-default-D]IN=vti0 OUT= SRC=fc00::1 DST=fc00::2 LEN=84 TC=0 HOPLIMIT=255 FLOWLBL=396288 PROTO=ICMPv6 TYPE=135 CODE=0",
                new("fc00::1", "fc00::2", null, null, EventProtocol.Icmpv6, EventAction.Deny)
            },
        };
}
