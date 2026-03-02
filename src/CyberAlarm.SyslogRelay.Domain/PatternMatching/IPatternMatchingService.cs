using CyberAlarm.SyslogRelay.Common.Models;

namespace CyberAlarm.SyslogRelay.Domain.PatternMatching;

internal interface IPatternMatchingService
{
    Task<PatternMatchResult?> MatchPatternAsync(string log, CancellationToken cancellationToken);
}
