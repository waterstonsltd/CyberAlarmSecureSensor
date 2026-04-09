using BenchmarkDotNet.Attributes;
using CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;
using CyberAlarm.SyslogRelay.Domain.Parsing;

namespace CyberAlarm.SyslogRelay.Benchmarks;

[MemoryDiagnoser]
public class SophosUtmParserBenchmarks
{
    private KeyValueParser _parser = null!;
    private string[] _lines = [];

    [GlobalSetup]
    public void Setup()
    {
        // Config mirrors docs/parsers/sophos-utm.json exactly
        var config = new KeyValueParserConfig
        {
            UseRegex = true,
            SourceIpKeys = ["srcip"],
            DestinationIpKeys = ["dstip"],
            SourcePortKeys = ["srcport"],
            IsSourcePortOptional = true,
            DestinationPortKeys = ["dstport"],
            IsDestinationPortOptional = true,
            ProtocolKeys = ["proto"],
            ActionKeys = ["action"],
            AllowActionValues = ["accept", "alert", "DNS request", "log"],
            DenyActionValues = ["ICMP flood", "reject", "SYN flood", "UDP flood"],
            DropActionValues = ["drop"],
        };

        _parser = new KeyValueParser();
        _parser.Initialise(config);
        _lines = File.ReadAllLines("test-data/sophos-utm-local-test.log");
    }

    [Benchmark]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1707", Justification = "BenchmarkDotNet convention")]
    public bool Parse_AllLines()
    {
        var lastResult = false;
        foreach (var line in _lines)
            lastResult = _parser.Parse(line).IsSuccess;
        return lastResult;
    }
}
