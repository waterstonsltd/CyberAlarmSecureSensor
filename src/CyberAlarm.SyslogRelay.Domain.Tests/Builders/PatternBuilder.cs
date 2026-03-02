using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Common.Status.Models;
using Pattern = CyberAlarm.SyslogRelay.Domain.PatternMatching.Pattern;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class PatternBuilder
{
    private readonly string _name = Guid.NewGuid().ToString();
    private readonly IParser _parser = Substitute.For<IParser>();
    private readonly List<PatternRule> _rules = [];

    private int _priority = 100;

    public Pattern Build() => new(_name, _parser, _priority, _rules);

    public PatternBuilder WithPriority(int priority)
    {
        _priority = priority;
        return this;
    }

    public PatternBuilder WithRule(RuleType ruleType, List<string> values, int? minimalCount = null)
    {
        _rules.Add(new PatternRule
        {
            Type = ruleType,
            Values = values,
            MinimumCount = minimalCount,
        });

        return this;
    }

    public PatternBuilder WithStartsWithRule(List<string> values) =>
        WithRule(RuleType.StartsWith, values);

    public PatternBuilder WithEndsWithRule(List<string> values) =>
        WithRule(RuleType.EndsWith, values);

    public PatternBuilder WithContainsAllRule(List<string> values) =>
        WithRule(RuleType.ContainsAll, values);

    public PatternBuilder WithContainsAnyRule(List<string> values) =>
        WithRule(RuleType.ContainsAny, values);

    public PatternBuilder WithMustNotContainRule(List<string> values) =>
        WithRule(RuleType.MustNotContain, values);

    public PatternBuilder WithMinimumMatchesRule(List<string> values, int minimumCount) =>
        WithRule(RuleType.MinimumMatches, values, minimumCount);

    public PatternBuilder WithLengthRangeRule(int minimumCount) =>
        WithRule(RuleType.LengthRange, [], minimumCount);
}
