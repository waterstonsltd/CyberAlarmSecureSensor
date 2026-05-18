using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Status;

public class StatusNotModifiedWarning() : Error("Status not modified.")
{
}
