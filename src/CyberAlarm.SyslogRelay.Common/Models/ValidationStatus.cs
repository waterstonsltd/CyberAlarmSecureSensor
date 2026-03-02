namespace CyberAlarm.SyslogRelay.Common.Models;

public enum ValidationStatus
{
    Success,
    UnableToPatternMatch,
    UnableToParse,
    LocalOnlyEvent,
}
