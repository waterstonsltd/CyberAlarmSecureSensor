using CyberAlarm.SyslogRelay.Common.Status.Models;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Status;

public interface IStatusService
{
    Task<RelayStatus> GetStatusAsync(CancellationToken cancellationToken);

    Task<Result<RelayStatus>> RefreshStatusAsync(CancellationToken cancellationToken);
}
