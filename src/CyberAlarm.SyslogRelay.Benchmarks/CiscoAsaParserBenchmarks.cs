using BenchmarkDotNet.Attributes;
using CyberAlarm.SyslogRelay.Domain.Parsing.Cisco;

namespace CyberAlarm.SyslogRelay.Benchmarks;

[MemoryDiagnoser]
public class CiscoAsaParserBenchmarks
{
    private CiscoAsaParser _parser = null!;
    private string[] _lines = [];

    [GlobalSetup]
    public void Setup()
    {
        _parser = new CiscoAsaParser();
        _parser.Initialise(null);
        _lines = File.ReadAllLines("test-data/cisco-asa-local-test.log");
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
