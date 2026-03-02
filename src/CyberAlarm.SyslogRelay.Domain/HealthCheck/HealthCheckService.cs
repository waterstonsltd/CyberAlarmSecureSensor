using CyberAlarm.SyslogRelay.Domain.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.HealthCheck;

internal sealed class HealthCheckService : IHealthCheckService, IDisposable
{
    private readonly IFileManager _fileManager;
    private readonly ILogger<HealthCheckService> _logger;

    private readonly string _healthCheckFilePath;
    private readonly HashSet<string> _registeredServices = [];
    private readonly SemaphoreSlim _semaphoreSlim = new(1, 1);

    public HealthCheckService(
        IFileManager fileManager,
        IOptions<HealthCheckOptions> options,
        ILogger<HealthCheckService> logger)
    {
        _fileManager = fileManager;
        _logger = logger;
        _healthCheckFilePath = Path.Combine(fileManager.GetDataPath(), "healthcheck.json");

        foreach (var service in options.Value.ServicesToRegister)
        {
            _registeredServices.Add(service);
        }
    }

    public void Dispose() => _semaphoreSlim.Dispose();

    public void Reset()
    {
        if (!_fileManager.Exists(_healthCheckFilePath))
        {
            return;
        }

        try
        {
            _fileManager.Delete(_healthCheckFilePath);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to reset health checks.");
        }
    }

    public async Task<HealthCheckResult> CheckHealthAsync(CancellationToken cancellationToken)
    {
        var healthChecks = await _fileManager.DeserialiseFromFileAsync<Dictionary<string, HealthCheckEntry>>(_healthCheckFilePath, cancellationToken);
        if (healthChecks is null)
        {
            return new(HealthStatus.Unhealthy, "No health checks found.");
        }

        foreach (var service in _registeredServices)
        {
            if (!healthChecks.TryGetValue(service, out var healthCheck))
            {
                return new(HealthStatus.Unhealthy, $"Health check for service '{service}' not found.");
            }

            if (healthCheck.Status == HealthStatus.Unhealthy)
            {
                return new(HealthStatus.Unhealthy, $"Service '{service}' is unhealthy.");
            }
        }

        return new(HealthStatus.Healthy, "All services are healthy.");
    }

    public Task SetHealthyAsync(string service, CancellationToken cancellationToken) =>
        SetHealthAsync(service, HealthStatus.Healthy, cancellationToken);

    public Task SetUnhealthyAsync(string service, CancellationToken cancellationToken) =>
        SetHealthAsync(service, HealthStatus.Unhealthy, cancellationToken);

    private async Task SetHealthAsync(string service, HealthStatus status, CancellationToken cancellationToken)
    {
        if (!_registeredServices.Contains(service))
        {
            throw new InvalidOperationException($"Service '{service}' is not registered.");
        }

        await _semaphoreSlim.WaitAsync(cancellationToken);

        try
        {
            _logger.LogDebug("Persisting health status '{HealthStatus}' for '{Service}'.", status, service);
            await Persist(service, new(DateTime.UtcNow, status), cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to persist health status '{HealthStatus}' for '{Service}'.", status, service);
        }
        finally
        {
            _semaphoreSlim.Release();
        }
    }

    private async Task Persist(string serviceName, HealthCheckEntry healthCheck, CancellationToken cancellationToken)
    {
        var healhChecks = await _fileManager.DeserialiseFromFileAsync<Dictionary<string, HealthCheckEntry>>(_healthCheckFilePath, cancellationToken) ?? [];
        healhChecks[serviceName] = healthCheck;

        await _fileManager.SerialiseToFileAsync(healhChecks, _healthCheckFilePath, cancellationToken);
    }
}
