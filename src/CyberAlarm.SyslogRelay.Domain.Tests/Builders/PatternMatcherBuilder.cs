using CyberAlarm.SyslogRelay.Domain.PatternMatching;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class PatternMatcherBuilder
{
    private readonly List<Pattern> _patterns = [];
    private readonly int _scanLength = 100;

    public PatternMatcher Build() => new(_patterns, _scanLength);

    public PatternMatcherBuilder WithPatterns(params Pattern[] patterns)
    {
        _patterns.AddRange(patterns);
        return this;
    }
}
