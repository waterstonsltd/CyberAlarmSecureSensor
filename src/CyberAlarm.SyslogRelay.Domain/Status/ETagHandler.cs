using CyberAlarm.SyslogRelay.Domain.State;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Status;

internal sealed class ETagHandler(IStateService stateService, ILogger<ETagHandler> logger) : DelegatingHandler
{
    private readonly IStateService _stateService = stateService;
    private readonly ILogger<ETagHandler> _logger = logger;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var state = await _stateService.GetStateAsync(cancellationToken);

        if (!string.IsNullOrEmpty(state.StatusETag))
        {
            _logger.LogDebug("Adding If-None-Match header with etag: {ETag}", state.StatusETag);
            request.Headers.Add("If-None-Match", state.StatusETag);
        }

        var response = await base.SendAsync(request, cancellationToken);

        if (response.IsSuccessStatusCode &&
            response.Headers.TryGetValues("ETag", out var etagValues))
        {
            var etag = etagValues.First();

            _logger.LogDebug("Saving etag from response to state: {ETag}", etag);
            state = state with { StatusETag = etag };
            await _stateService.SetStateAsync(state, cancellationToken);
        }

        return response;
    }
}
