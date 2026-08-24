namespace CyberAlarm.SyslogRelay.Common.Models;

public sealed record EventSource(IngestionMethod IngestionMethod, string Source);
