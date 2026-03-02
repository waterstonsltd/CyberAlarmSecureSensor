namespace CyberAlarm.SyslogRelay.Common.EventBundler.Models;

public sealed record EventsMetaData(
    string IngestionMethod,
    string Source,
    int TotalEvents,
    int UnmatchedEvents,
    int UnparsedEvents,
    int LocalOnlyEvents);
