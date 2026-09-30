using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Parsing;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Parsing;

public sealed class CefParserTests
{
    private readonly CefParser _unitUnderTest = new();

    [Theory]
    [InlineData("|||||||")]
    [InlineData("x")]
    [InlineData("x|x")]
    [InlineData("x|x|x|x|x|x|x")]
    [InlineData("x|x|x|x|x|x|x|x")]
    [InlineData("x|CEF:|x|x|x|x|x|x")]
    public void Parse_should_fail_when_log_has_incorrect_format(string log)
    {
        // Arrange
        var config = new ParserConfigBuilder().Build();
        _unitUnderTest.Initialise(config);

        // Act
        var result = _unitUnderTest.Parse(log);

        // Assert
        Assert.True(result.IsFailed);
        Assert.Equal("Log format is invalid.", result.ErrorMessage);
    }

    [Fact]
    public void Parse_should_fail_when_log_does_not_contain_required_value()
    {
        // Arrange
        var config = new ParserConfigBuilder()
            .WithSourceIpKeys("src")
            .WithOptional()
            .Build();
        _unitUnderTest.Initialise(config);

        // Act
        var result = _unitUnderTest.Parse("CEF:|x|x|x|x|x|x|x");

        // Assert
        Assert.True(result.IsFailed);
        Assert.Equal("Failed to parse event.", result.ErrorMessage);
    }

    [Theory]
    [MemberData(nameof(GenericCefTestLogs), MemberType = typeof(CefParserTests))]
    public void Parse_should_succeed_when_log_has_correct_format(ParserConfig config, string log, ParseResult parseResult)
    {
        // Arrange
        _unitUnderTest.Initialise(config);

        // Act
        var result = _unitUnderTest.Parse(log);

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal(parseResult, result.Value);
    }

    public static TheoryData<ParserConfig, string, ParseResult> GenericCefTestLogs()
    {
        var config = new ParserConfigBuilder()
            .WithSourceIpKeys("src")
            .WithDestinationIpKeys("dst")
            .WithSourcePortKeys("spt")
            .WithDestinationPortKeys("dpt")
            .WithProtocolKeys("proto")
            .WithActionKeys("act")
            .WithActionValues(["accept"], ["deny"])
            .WithOptional()
            .Build();

        return new()
        {
            {
                config,
                "CEF:0|x|x|x|x|x|x|src=x",
                new("x", null, null, null, EventProtocol.Unknown, EventAction.Unknown)
            },
            {
                config,
                "CEF:0|Fortinet|Fortigate|v6.0.3|00013|traffic:forward|3|src=192.0.2.1 dst=10.0.1.50 spt=1234 dpt=4321 proto=6 act=accept",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Allow)
            },
            {
                config,
                "CEF:0|Palo Alto Networks|PAN-OS|2.0|TRAFFIC|end|3|src=192.0.2.1 dst=10.0.1.50 spt=1234 dpt=4321 proto=6 act=deny",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Deny)
            },
        };
    }

    [Theory]
    [MemberData(nameof(PaloAltoLogForwarderTestLogs), MemberType = typeof(CefParserTests))]
    public void Parse_should_succeed_for_palo_alto_log_forwarder_logs(string log, ParseResult parseResult)
    {
        // Arrange — mirrors docs/parsers/paloalto-cef.json
        var config = new ParserConfigBuilder()
            .WithSourceIpKeys("src")
            .WithDestinationIpKeys("dst")
            .WithSourcePortKeys("spt")
            .WithDestinationPortKeys("dpt")
            .WithProtocolKeys("proto")
            .WithActionKeys("act")
            .WithActionValues(["allow"], ["deny", "reset-client", "reset-server", "reset-both"], ["drop", "sinkhole"])
            .WithOptional()
            .Build();
        _unitUnderTest.Initialise(config);

        // Act
        var result = _unitUnderTest.Parse(log);

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal(parseResult, result.Value);
    }

    public static TheoryData<string, ParseResult> PaloAltoLogForwarderTestLogs() => new()
    {
        {
            "<14>Sep 29 13:34:42 1494111629-log-forwarder-logfwd01-56ccc77cc5-d594w logforwarder CEF:0|Palo Alto Networks|LF|2.0|TRAFFIC|deny|3|dtz=UTC rt=Sep 29 2026 13:34:38 deviceExternalId=7DDE85235C33143 PanOSConfigVersion=10.2 start=Sep 29 2026 13:34:36 src=10.167.40.72 c6a2=10.167.40.72 c6a2Label=Source IPv6 Address dst=203.0.113.10 c6a3=203.0.113.10 c6a3Label=Destination IPv6 Address sourceTranslatedAddress=198.51.100.3 destinationTranslatedAddress=203.0.113.10 cs1=Deny Quic cs1Label=Rule suser=user@example.com duser= app=quic-base cs3=vsys1 cs3Label=VirtualLocation cs4=trust cs4Label=FromZone cs5=untrust cs5Label=ToZone deviceInboundInterface=tunnel.1 deviceOutboundInterface=tunnel.2001 cs6=Cortex Data Lake cs6Label=LogSetting cn1=7916107 cn1Label=SessionID cnt=1 spt=49876 dpt=443 sourceTranslatedPort=13578 destinationTranslatedPort=443 proto=udp act=drop PanOSBytes=1292 out=1292 in=0 cn2=1 cn2Label=PacketsTotal PanOSSessionStartTime=Sep 29 2026 13:34:36 cn3=0 cn3Label=SessionDuration cs2=any cs2Label=URLCategory reason=policy-deny dvchost=GP cloud service cat=from-policy PanOSSourceUUID= PanOSParentStarttime=Jan 01 1970 00:00:00 PanOSTunnel=N/A PanOSNSSAINetworkSliceDifferentiator=",
            new("10.167.40.72", "203.0.113.10", 49876, 443, EventProtocol.Udp, EventAction.Drop)
        },
        {
            "<14>Sep 29 14:21:30 1494111629-log-forwarder-logfwd01-56ccc77cc5-d594w logforwarder CEF:0|Palo Alto Networks|LF|2.0|THREAT|vulnerability|5|dtz=UTC rt=Sep 29 2026 14:21:29 deviceExternalId=024209003441 PanOSConfigVersion=11.2 start=Sep 29 2026 14:21:24 src=203.0.113.51 c6a2=203.0.113.51 c6a2Label=Source IPv6 Address dst=198.51.100.131 c6a3=198.51.100.131 c6a3Label=Destination IPv6 Address cs1=Inbound- portal.example.com cs1Label=Rule suser= duser= app=web-browsing cs3=vsys1 cs3Label=VirtualLocation cs4=Internet cs4Label=FromZone cs5=v1508_Untrust cs5Label=ToZone cnt=1 spt=56362 dpt=80 sourceTranslatedPort=56362 destinationTranslatedPort=80 proto=tcp act=alert request=index.php dvchost=GP cloud service",
            new("203.0.113.51", "198.51.100.131", 56362, 80, EventProtocol.Tcp, EventAction.Unknown)
        },
        {
            "<14>Sep 29 14:22:33 1494111629-log-forwarder-logfwd01-56ccc77cc5-d594w logforwarder CEF:0|Palo Alto Networks|LF|2.0|THREAT|spyware|3|dtz=UTC rt=Sep 29 2026 14:22:30 deviceExternalId=7DDE85235C33143 PanOSConfigVersion=10.2 start=Sep 29 2026 14:22:25 src=10.167.38.76 c6a2=10.167.38.76 c6a2Label=Source IPv6 Address dst=10.167.32.1 c6a3=10.167.32.1 c6a3Label=Destination IPv6 Address sourceTranslatedAddress= destinationTranslatedAddress= cs1=intrazone-default cs1Label=Rule suser=user@example.com duser= app=dns-base cs3=vsys1 cs3Label=VirtualLocation cnt=1 spt=62007 dpt=53 sourceTranslatedPort=0 destinationTranslatedPort=0 proto=udp act=sinkhole request=example.com PanOSThreatID=Grayware:example.com(109010002) flexString2=client to server flexString2Label=DirectionOfAttack dvchost=GP cloud service PanOSThreatCategory=dns-grayware",
            new("10.167.38.76", "10.167.32.1", 62007, 53, EventProtocol.Udp, EventAction.Drop)
        },
    };
}
