using BenchmarkDotNet.Attributes;
using CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;
using CyberAlarm.SyslogRelay.Domain.Parsing;

namespace CyberAlarm.SyslogRelay.Benchmarks;

[MemoryDiagnoser]
public class JsonParserBenchmarks
{
    private JsonParser _parser = null!;
    private string[] _lines = [];

    [GlobalSetup]
    public void Setup()
    {
        // Config mirrors docs/parsers/smoothwall-firewall-json.json exactly
        var config = new JsonParserConfig
        {
            JsonStartToken = "firewall: ",
            ProtocolIsNumber = true,
            SourceIpKeys = ["src"],
            DestinationIpKeys = ["dst"],
            IsDestinationIpOptional = true,
            SourcePortKeys = ["spt"],
            IsSourcePortOptional = true,
            DestinationPortKeys = ["dpt"],
            IsDestinationPortOptional = true,
            ProtocolKeys = ["proto"],
            IsProtocolOptional = true,
            ActionKeys = ["action"],
            IsActionOptional = true,
            AllowActionValues = ["accept"],
            DropActionValues = ["drop"],
        };

        _parser = new JsonParser();
        _parser.Initialise(config);
        _lines = File.ReadAllLines("test-data/smoothwall-firewall-json-local-test.log");
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
