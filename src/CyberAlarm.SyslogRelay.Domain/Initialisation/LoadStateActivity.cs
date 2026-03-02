using CyberAlarm.SyslogRelay.Domain.State;
using FluentResults;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Initialisation;

internal sealed class LoadStateActivity(IStateService stateService, ILogger<LoadStateActivity> logger) : IStartupActivity
{
    private readonly IStateService _stateService = stateService;
    private readonly ILogger<LoadStateActivity> _logger = logger;

    public async Task<Result> RunAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Load state.");
        var state = await _stateService.GetStateAsync(cancellationToken);

        if (state.IsUploadBlocked)
        {
            return Result.Fail("Upload is blocked.");
        }

        return Result.Ok();
    }
}
