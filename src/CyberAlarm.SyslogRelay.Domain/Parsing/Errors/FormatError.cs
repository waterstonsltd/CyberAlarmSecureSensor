using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Parsing.Errors;

internal sealed class FormatError(string message) : Error(message)
{
    public FormatError()
        : this("Log format is invalid.")
    {
    }
}
