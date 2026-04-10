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
}
