using CyberAlarm.SyslogRelay.Domain.Tests.Builders;

namespace CyberAlarm.SyslogRelay.Domain.Tests.PatternMatching;

public sealed class PatternMatcherTests
{
    private readonly PatternMatcherBuilder _builder = new();

    [Fact]
    public void PatternMatcher_should_sort_patterns_by_priority()
    {
        // Arrange
        var nonMatchingPattern = new PatternBuilder()
            .WithPriority(1)
            .WithStartsWithRule(["x"])
            .Build();
        var matchingPattern = new PatternBuilder()
            .WithPriority(10)
            .WithStartsWithRule(["x"])
            .Build();

        var unitUnderTest = _builder
            .WithPatterns(nonMatchingPattern, matchingPattern)
            .Build();

        // Act
        var result = unitUnderTest.TryMatch("x", out var match);

        // Assert
        Assert.True(result);
        Assert.NotNull(match);
        Assert.Equal(matchingPattern.Name, match.PatternName);
    }

    [Fact]
    public void TryMatch_should_return_false_when_no_patterns_are_passed()
    {
        // Arrange
        var unitUnderTest = _builder.Build();

        // Act
        var result = unitUnderTest.TryMatch("x", out var match);

        // Assert
        Assert.False(result);
        Assert.Null(match);
    }

    [Fact]
    public void TryMatch_should_return_false_when_pattern_with_multiple_rules_is_not_matched()
    {
        // Arrange
        var pattern = new PatternBuilder()
            .WithStartsWithRule(["a", "b", "c"])
            .WithEndsWithRule(["x", "y", "z"])
            .WithLengthRangeRule(3)
            .Build();

        var unitUnderTest = _builder
            .WithPatterns(pattern)
            .Build();

        // Act
        var result = unitUnderTest.TryMatch("az", out var match);

        // Assert
        Assert.False(result);
        Assert.Null(match);
    }

    [Fact]
    public void TryMatch_should_return_true_when_log_matches_pattern_with_multiple_rules()
    {
        // Arrange
        var pattern = new PatternBuilder()
            .WithStartsWithRule(["a", "b", "c"])
            .WithEndsWithRule(["x", "y", "z"])
            .WithLengthRangeRule(3)
            .Build();

        var unitUnderTest = _builder
            .WithPatterns(pattern)
            .Build();

        // Act
        var result = unitUnderTest.TryMatch("a2z", out var match);

        // Assert
        Assert.True(result);
        Assert.NotNull(match);
        Assert.Equal(pattern.Name, match.PatternName);
    }

    [Fact]
    public void TryMatch_should_return_false_when_pattern_with_startswith_rule_is_not_matched()
    {
        // Arrange
        var pattern1 = new PatternBuilder()
            .WithStartsWithRule(["a", "b", "c"])
            .Build();
        var pattern2 = new PatternBuilder()
            .WithStartsWithRule(["1", "z"])
            .Build();

        var unitUnderTest = _builder
            .WithPatterns(pattern1, pattern2)
            .Build();

        // Act
        var result = unitUnderTest.TryMatch("x", out var match);

        // Assert
        Assert.False(result);
        Assert.Null(match);
    }

    [Fact]
    public void TryMatch_should_return_true_when_log_matches_pattern_with_startswith_rule()
    {
        // Arrange
        var nonMatchingPattern = new PatternBuilder()
            .WithStartsWithRule(["a", "b", "c"])
            .Build();
        var matchingPattern = new PatternBuilder()
            .WithStartsWithRule(["1", "z"])
            .Build();

        var unitUnderTest = _builder
            .WithPatterns(nonMatchingPattern, matchingPattern)
            .Build();

        // Act
        var result = unitUnderTest.TryMatch("zyx", out var match);

        // Assert
        Assert.True(result);
        Assert.NotNull(match);
        Assert.Equal(matchingPattern.Name, match.PatternName);
    }

    [Fact]
    public void TryMatch_should_return_false_when_pattern_with_endswith_rule_is_not_matched()
    {
        // Arrange
        var pattern1 = new PatternBuilder()
            .WithEndsWithRule(["a", "b", "c"])
            .Build();
        var pattern2 = new PatternBuilder()
            .WithEndsWithRule(["1", "z"])
            .Build();

        var unitUnderTest = _builder
            .WithPatterns(pattern1, pattern2)
            .Build();

        // Act
        var result = unitUnderTest.TryMatch("x", out var match);

        // Assert
        Assert.False(result);
        Assert.Null(match);
    }

    [Fact]
    public void TryMatch_should_return_true_when_log_matches_pattern_with_endswith_rule()
    {
        // Arrange
        var nonMatchingPattern = new PatternBuilder()
            .WithEndsWithRule(["a", "b", "c"])
            .Build();
        var matchingPattern = new PatternBuilder()
            .WithEndsWithRule(["1", "z"])
            .Build();

        var unitUnderTest = _builder
            .WithPatterns(nonMatchingPattern, matchingPattern)
            .Build();

        // Act
        var result = unitUnderTest.TryMatch("xyz", out var match);

        // Assert
        Assert.True(result);
        Assert.NotNull(match);
        Assert.Equal(matchingPattern.Name, match.PatternName);
    }

    [Fact]
    public void TryMatch_should_return_false_when_pattern_with_containsall_rule_is_not_matched()
    {
        // Arrange
        var pattern1 = new PatternBuilder()
            .WithContainsAllRule(["a", "b", "c"])
            .Build();
        var pattern2 = new PatternBuilder()
            .WithContainsAllRule(["1", "z"])
            .Build();

        var unitUnderTest = _builder
            .WithPatterns(pattern1, pattern2)
            .Build();

        // Act
        var result = unitUnderTest.TryMatch("x", out var match);

        // Assert
        Assert.False(result);
        Assert.Null(match);
    }

    [Fact]
    public void TryMatch_should_return_true_when_log_matches_pattern_with_containsall_rule()
    {
        // Arrange
        var nonMatchingPattern = new PatternBuilder()
            .WithContainsAllRule(["a", "b", "c"])
            .Build();
        var matchingPattern = new PatternBuilder()
            .WithContainsAllRule(["1", "z"])
            .Build();

        var unitUnderTest = _builder
            .WithPatterns(nonMatchingPattern, matchingPattern)
            .Build();

        // Act
        var result = unitUnderTest.TryMatch("z1", out var match);

        // Assert
        Assert.True(result);
        Assert.NotNull(match);
        Assert.Equal(matchingPattern.Name, match.PatternName);
    }

    [Fact]
    public void TryMatch_should_return_false_when_pattern_with_containsany_rule_is_not_matched()
    {
        // Arrange
        var pattern1 = new PatternBuilder()
            .WithContainsAnyRule(["a", "b", "c"])
            .Build();
        var pattern2 = new PatternBuilder()
            .WithContainsAnyRule(["1", "z"])
            .Build();

        var unitUnderTest = _builder
            .WithPatterns(pattern1, pattern2)
            .Build();

        // Act
        var result = unitUnderTest.TryMatch("x", out var match);

        // Assert
        Assert.False(result);
        Assert.Null(match);
    }

    [Fact]
    public void TryMatch_should_return_true_when_log_matches_pattern_with_containsany_rule()
    {
        // Arrange
        var nonMatchingPattern = new PatternBuilder()
            .WithContainsAnyRule(["a", "b", "c"])
            .Build();
        var matchingPattern = new PatternBuilder()
            .WithContainsAnyRule(["1", "z"])
            .Build();

        var unitUnderTest = _builder
            .WithPatterns(nonMatchingPattern, matchingPattern)
            .Build();

        // Act
        var result = unitUnderTest.TryMatch("xyz", out var match);

        // Assert
        Assert.True(result);
        Assert.NotNull(match);
        Assert.Equal(matchingPattern.Name, match.PatternName);
    }

    [Fact]
    public void TryMatch_should_return_false_when_pattern_with_minimummatches_rule_is_not_matched()
    {
        // Arrange
        var pattern1 = new PatternBuilder()
            .WithMinimumMatchesRule(["ab", "cd", "ef"], 3)
            .Build();
        var pattern2 = new PatternBuilder()
            .WithMinimumMatchesRule(["12", "yz"], 3)
            .Build();

        var unitUnderTest = _builder
            .WithPatterns(pattern1, pattern2)
            .Build();

        // Act
        var result = unitUnderTest.TryMatch("xyz xyz", out var match);

        // Assert
        Assert.False(result);
        Assert.Null(match);
    }

    [Fact]
    public void TryMatch_should_return_true_when_log_matches_pattern_with_minimummatches_rule()
    {
        // Arrange
        var nonMatchingPattern = new PatternBuilder()
            .WithMinimumMatchesRule(["ab", "cd", "ef"], 3)
            .Build();
        var matchingPattern = new PatternBuilder()
            .WithMinimumMatchesRule(["12", "yz"], 3)
            .Build();

        var unitUnderTest = _builder
            .WithPatterns(nonMatchingPattern, matchingPattern)
            .Build();

        // Act
        var result = unitUnderTest.TryMatch("xyz xyz xyz", out var match);

        // Assert
        Assert.True(result);
        Assert.NotNull(match);
        Assert.Equal(matchingPattern.Name, match.PatternName);
    }

    [Fact]
    public void TryMatch_should_return_false_when_pattern_with_lengthrange_rule_is_not_matched()
    {
        // Arrange
        var pattern1 = new PatternBuilder()
            .WithLengthRangeRule(3)
            .Build();
        var pattern2 = new PatternBuilder()
            .WithLengthRangeRule(5)
            .Build();

        var unitUnderTest = _builder
            .WithPatterns(pattern1, pattern2)
            .Build();

        // Act
        var result = unitUnderTest.TryMatch("x", out var match);

        // Assert
        Assert.False(result);
        Assert.Null(match);
    }

    [Fact]
    public void TryMatch_should_return_true_when_log_matches_pattern_with_lengthrange_rule()
    {
        // Arrange
        var nonMatchingPattern = new PatternBuilder()
            .WithLengthRangeRule(5)
            .Build();
        var matchingPattern = new PatternBuilder()
            .WithLengthRangeRule(3)
            .Build();

        var unitUnderTest = _builder
            .WithPatterns(nonMatchingPattern, matchingPattern)
            .Build();

        // Act
        var result = unitUnderTest.TryMatch("xyz", out var match);

        // Assert
        Assert.True(result);
        Assert.NotNull(match);
        Assert.Equal(matchingPattern.Name, match.PatternName);
    }

    [Fact]
    public void TryMatch_should_match_cisco_firepower_log()
    {
        // Arrange — mirrors the Cisco Firepower pattern rules in docs/parsers/cisco-firepower.json
        var pattern = new PatternBuilder()
            .WithContainsAnyRule(["%FTD-", "%NGIPS-"])
            .WithMustNotContainRule(["%ASA-", "%FWSM-", "%PIX-", "CEF:"])
            .Build();

        var unitUnderTest = _builder
            .WithPatterns(pattern)
            .Build();

        const string ftdLog = "<113>2026-02-12T14:05:27Z cisco-firepower.internal.cloudapp.net  %FTD-1-430002: EventPriority: Low, AccessControlRuleAction: Block, SrcIP: 10.20.1.4, DstIP: 85.30.190.138, SrcPort: 60846, DstPort: 22, Protocol: tcp";

        // Act
        var result = unitUnderTest.TryMatch(ftdLog, out var match);

        // Assert
        Assert.True(result);
        Assert.NotNull(match);
        Assert.Equal(pattern.Name, match.PatternName);
    }

    [Fact]
    public void TryMatch_should_match_cisco_ngips_log()
    {
        // Arrange — older Sourcefire/NGIPS devices use %NGIPS- prefix with the same body format
        var pattern = new PatternBuilder()
            .WithContainsAnyRule(["%FTD-", "%NGIPS-"])
            .WithMustNotContainRule(["%ASA-", "%FWSM-", "%PIX-", "CEF:"])
            .Build();

        var unitUnderTest = _builder
            .WithPatterns(pattern)
            .Build();

        const string ngipsLog = "<113>2026-02-12T14:05:27Z sourcefire.internal.cloudapp.net  %NGIPS-1-430002: EventPriority: Low, AccessControlRuleAction: Block, SrcIP: 10.20.1.4, DstIP: 85.30.190.138, SrcPort: 60846, DstPort: 22, Protocol: tcp";

        // Act
        var result = unitUnderTest.TryMatch(ngipsLog, out var match);

        // Assert
        Assert.True(result);
        Assert.NotNull(match);
        Assert.Equal(pattern.Name, match.PatternName);
    }

    [Fact]
    public void TryMatch_should_not_match_cisco_firepower_pattern_for_cisco_asa_log()
    {
        // Arrange — ASA log must NOT match the Firepower pattern (MustNotContain: %ASA-)
        var pattern = new PatternBuilder()
            .WithContainsAnyRule(["%FTD-", "%NGIPS-"])
            .WithMustNotContainRule(["%ASA-", "%FWSM-", "%PIX-", "CEF:"])
            .Build();

        var unitUnderTest = _builder
            .WithPatterns(pattern)
            .Build();

        const string asaLog = "<164>Apr 17 2026 10:00:00 asa-fw %ASA-4-106023: Deny tcp src inside:192.168.1.100/1234 dst outside:1.2.3.4/80";

        // Act
        var result = unitUnderTest.TryMatch(asaLog, out var match);

        // Assert
        Assert.False(result);
        Assert.Null(match);
    }
}
