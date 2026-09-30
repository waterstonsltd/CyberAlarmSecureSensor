using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Parsing.WatchGuard;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Parsing;

public sealed class WatchGuardDimensionParserTests
{
    private readonly WatchGuardDimensionParser _unitUnderTest = new();

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
    [MemberData(nameof(TestLogs), MemberType = typeof(WatchGuardDimensionParserTests))]
    public void Parse_should_succeed_for_valid_dimension_logs(string log, ParseResult expected)
    {
        _unitUnderTest.Initialise(Config);

        var result = _unitUnderTest.Parse(log);

        Assert.True(result.IsSuccess);
        Assert.Equal(expected, result.Value);
    }

    public static TheoryData<string, ParseResult> TestLogs =>
        new()
        {
            // Allow UDP without hostname (date time action srcIp dstIp service/proto srcPort dstPort)
            {
                "2024-01-15 10:30:45 Allow 192.168.1.100 8.8.8.8 DNS/udp 54321 53",
                new("192.168.1.100", "8.8.8.8", 54321, 53, EventProtocol.Udp, EventAction.Allow)
            },
            // Deny TCP without hostname
            {
                "2024-01-15 10:31:00 Deny 10.20.1.5 85.234.74.60 HTTP/tcp 62664 80",
                new("10.20.1.5", "85.234.74.60", 62664, 80, EventProtocol.Tcp, EventAction.Deny)
            },
            // Allow TCP with hostname (date time hostname action srcIp dstIp service/proto srcPort dstPort)
            {
                "2024-01-15 10:32:00 Firebox Allow 10.20.1.4 135.233.95.144 HTTPS/tcp 63845 443",
                new("10.20.1.4", "135.233.95.144", 63845, 443, EventProtocol.Tcp, EventAction.Allow)
            },
        };
}
