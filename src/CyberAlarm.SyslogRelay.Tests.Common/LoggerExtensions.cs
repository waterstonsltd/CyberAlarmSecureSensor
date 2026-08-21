using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Tests.Common;

public static class LoggerExtensions
{
    public static IEnumerable<(LogLevel? LogLevel, string? Message)> ReceivedLogs<T>(this ILogger<T> logger) =>
        logger.ReceivedCalls()
            .Where(call => call.GetMethodInfo().Name == "Log")
            .Select(call =>
            (
                LogLevel: call.GetArguments()[0] as LogLevel?,
                Message: (call.GetArguments()[2] ?? string.Empty).ToString()
            ))
            .ToList();
}
