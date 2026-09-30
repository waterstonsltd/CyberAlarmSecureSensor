using CyberAlarm.SyslogRelay.Common.Status.Models;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Status;

public interface IStatusClient
{
    Task<Result<RelayStatus>> GetStatusAsync(CancellationToken cancellationToken);
}
