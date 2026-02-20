using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Parsing;
using CyberAlarm.SyslogRelay.Domain.Status;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using StatusPattern = CyberAlarm.SyslogRelay.Common.Status.Models.Pattern;

namespace CyberAlarm.SyslogRelay.Domain.PatternMatching;

internal sealed class PatternMatchingService(
    IMemoryCache memoryCache,
    IStatusService statusService,
    IParserFactory parserFactory,
    IOptions<RelayOptions> options,
    ILogger<PatternMatchingService> logger) : IPatternMatchingService, IDisposable
{
    public const string PatternMatcherCacheKey = "PatternMatcher";

    private readonly IMemoryCache _memoryCache = memoryCache;
    private readonly IStatusService _statusService = statusService;
    private readonly IParserFactory _parserFactory = parserFactory;
    private readonly RelayOptions _options = options.Value;
    private readonly ILogger<PatternMatchingService> _logger = logger;

    private readonly SemaphoreSlim _lock = new(1, 1);

    public void Dispose() => _lock.Dispose();

    public async Task<PatternMatchResult?> MatchPatternAsync(string log, CancellationToken cancellationToken)
    {
        var patternMatcher = await GetPatternMatcher(cancellationToken);
        patternMatcher.TryMatch(log, out var match);

        return match;
    }

    private async Task<PatternMatcher> GetPatternMatcher(CancellationToken cancellationToken)
    {
        if (_memoryCache.TryGetValue<PatternMatcher>(PatternMatcherCacheKey, out var patternMatcher))
        {
            return patternMatcher!;
        }

        await _lock.WaitAsync(cancellationToken);

        try
        {
            // Double-check after acquiring lock
            if (_memoryCache.TryGetValue(PatternMatcherCacheKey, out patternMatcher))
            {
                return patternMatcher!;
            }

            var patterns = await GetPatterns(cancellationToken);
            patternMatcher = new PatternMatcher(patterns, _options.PatternMatchingScanLength);
            _memoryCache.Set(PatternMatcherCacheKey, patternMatcher, TimeSpan.FromSeconds(_options.PatternMatchingCacheDurationInSeconds));

            return patternMatcher;
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task<List<Pattern>> GetPatterns(CancellationToken cancellationToken)
    {
        var status = await _statusService.GetStatusAsync(cancellationToken);
        if (status.Patterns is null || status.Patterns.Length == 0)
        {
            _logger.LogWarning("No patterns found in status.");
            return [];
        }

        // Validate unique names
        EnsureNoDuplicates(status.Patterns);

        // Pre-hydrate parsers for all patterns
        return HydrateWithParsers(status.Patterns);
    }

    private void EnsureNoDuplicates(StatusPattern[] patterns)
    {
        var duplicates = patterns
            .GroupBy(p => p.Name)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToList();

        if (duplicates.Count != 0)
        {
            var duplicateList = string.Join(", ", duplicates);
            _logger.LogError("Duplicate pattern names found: {DuplicatePatterns}", duplicateList);
            throw new InvalidOperationException($"Duplicate pattern names found: {duplicateList}");
        }
    }

    private List<Pattern> HydrateWithParsers(StatusPattern[] patterns)
    {
        var parserPatterns = new List<Pattern>(patterns.Length);

        foreach (var pattern in patterns)
        {
            var parser = _parserFactory.Create(pattern.ParserClass);
            if (parser is null)
            {
                _logger.LogError("Pattern '{Pattern}' has missing parser '{Parser}'.", pattern.Name, pattern.ParserClass);
                continue;
            }

            parserPatterns.Add(new(pattern.Name, parser, pattern.Priority, pattern.Rules));
        }

        return parserPatterns;
    }
}
