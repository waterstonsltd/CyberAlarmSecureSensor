namespace CyberAlarm.SyslogRelay.Domain.Parsing.Cisco;

internal enum LogSeverity
{
    Unknown = 0,
    Alert = 1,
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notification = 5,
    Informational = 6,
    Debugging = 7,
}
