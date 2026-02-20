using CyberAlarm.SyslogRelay.Common.Status.Models;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Domain.State;
using FluentResults;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Status;

internal sealed class StatusService(
    IFileManager fileManager,
    IStateService stateService,
    IStatusClient statusClient,
    ILogger<StatusService> logger) : IStatusService
{
    private readonly IFileManager _fileManager = fileManager;
    private readonly IStateService _stateService = stateService;
    private readonly IStatusClient _statusClient = statusClient;
    private readonly ILogger<StatusService> _logger = logger;

    private readonly string _statusFilePath = Path.Combine(fileManager.GetDataPath(), "status.json");

    public async Task<RelayStatus> GetStatusAsync(CancellationToken cancellationToken)
    {
        _logger.LogDebug("Loading status from file.");
        var status = await ReadFromFile(cancellationToken);
        if (status != null)
        {
            return status;
        }

        _logger.LogError("Failed to load status from file.");
        throw new InvalidOperationException("Failed to load status from file.");
    }

    public Task<Result<RelayStatus>> RefreshStatusAsync(CancellationToken cancellationToken) =>
        RefreshStatus(cancellationToken);

    private async Task<Result<RelayStatus>> RefreshStatus(CancellationToken cancellationToken)
    {
        var result = await _statusClient.GetStatusAsync(cancellationToken);
        if (result.IsSuccess)
        {
            _logger.LogDebug("Writing status to file: {@Status}", result.Value);
            await WriteToFile(result.Value, cancellationToken);
            return result;
        }

        var errorMessagePrefix = result.HasError<StatusNotModifiedWarning>()
            ? "Skipping status refresh"
            : "Failed to refresh status";

        _logger.LogWarning("{Prefix}: {ErrorMessage} Attempting to read status from file.", errorMessagePrefix, result.ErrorMessage);

        var status = await ReadFromFile(cancellationToken);
        if (status != null)
        {
            _logger.LogDebug("Returning status from file.");
            return status;
        }

        await _stateService.UpdateStateAsync(state => state with { StatusETag = string.Empty }, cancellationToken);

        _logger.LogError("Failed to refresh status from endpoint and file: {ErrorMessage}", result.ErrorMessage);
        return Result.Fail<RelayStatus>($"Failed to refresh status from endpoint and file: {result.ErrorMessage}");
    }

    private Task<RelayStatus?> ReadFromFile(CancellationToken cancellationToken) =>
        _fileManager.DeserialiseFromFileAsync<RelayStatus>(_statusFilePath, cancellationToken);

    private Task WriteToFile(RelayStatus status, CancellationToken cancellationToken) =>
        _fileManager.SerialiseToFileAsync(status, _statusFilePath, cancellationToken);
}
