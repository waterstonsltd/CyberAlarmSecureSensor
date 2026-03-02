using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Common.Status.Models;

namespace CyberAlarm.SyslogRelay.Domain.PatternMatching;

internal sealed record Pattern(string Name, IParser Parser, int Priority, List<PatternRule> Rules);
