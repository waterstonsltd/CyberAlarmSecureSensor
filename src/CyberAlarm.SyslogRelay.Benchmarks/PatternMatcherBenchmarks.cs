using BenchmarkDotNet.Attributes;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Common.Status.Models;
using CyberAlarm.SyslogRelay.Domain.Parsing.Cisco;
using CyberAlarm.SyslogRelay.Domain.PatternMatching;
using DomainPattern = CyberAlarm.SyslogRelay.Domain.PatternMatching.Pattern;

namespace CyberAlarm.SyslogRelay.Benchmarks;

[MemoryDiagnoser]
public class PatternMatcherBenchmarks
{
    private PatternMatcher _patternMatcher = null!;
    private string[] _lines = [];

    [GlobalSetup]
    public void Setup()
    {
        var parser = new CiscoAsaParser();
        parser.Initialise(null);

        // Mirrors the real Cisco ASA pattern from docs/parsers/cisco-asa.json
        var ciscoPattern = new DomainPattern(
            Name: "Cisco ASA",
            Parser: parser,
            Priority: 100,
            Rules:
            [
                new PatternRule
                {
                    Type = RuleType.ContainsAny,
                    Values = ["%ASA-", "%FWSM-", "%PIX-"],
                },
                new PatternRule
                {
                    Type = RuleType.MustNotContain,
                    Values = ["CEF:"],
                },
            ],
            IgnoreIfContaining:
            [
                ": AAA ",
                "%ASA-6-305011",
                "%ASA-6-305012",
                "-111",
                "-713",
                "-715",
                "-716",
                "-722",
                "-750",
                "-751",
            ]);

        _patternMatcher = new PatternMatcher([ciscoPattern], scanLength: 200);
        _lines = File.ReadAllLines("test-data/cisco-asa-local-test.log");
    }

    [Benchmark]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1707", Justification = "BenchmarkDotNet convention")]
    public bool TryMatch_AllLines()
    {
        var lastResult = false;
        foreach (var line in _lines)
            lastResult = _patternMatcher.TryMatch(line, out _);
        return lastResult;
    }
}
