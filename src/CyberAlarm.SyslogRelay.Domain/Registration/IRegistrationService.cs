using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Registration;

public interface IRegistrationService
{
    Task<Result> RegisterAsync(CancellationToken cancellationToken);
}
