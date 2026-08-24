using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Initialisation;

public interface IStartupActivity
{
    Task<Result> RunAsync(CancellationToken cancellationToken);
}
