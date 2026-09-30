using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Registration;

public interface IRegistrationClient
{
    Task<Result> PostRegistrationAsync(RegistrationRequest request, CancellationToken cancellationToken);
}
