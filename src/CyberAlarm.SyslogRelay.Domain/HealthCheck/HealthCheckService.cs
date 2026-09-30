using CyberAlarm.SyslogRelay.Domain.Services;
using FluentResults;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using HealthChecks = System.Collections.Generic.Dictionary<string, CyberAlarm.SyslogRelay.Domain.HealthCheck.HealthCheckEntry?>;

namespace CyberAlarm.SyslogRelay.Domain.HealthCheck;

internal sealed class HealthCheckService(
    IFileManager fileManager,
    IOptions<HealthCheckOptions> options,
    ILogger<HealthCheckService> logger) : IHealthCheckService, IDisposable
{
    private readonly IFileManager _fileManager = fileManager;
    private readonly HealthCheckOptions _options = options.Value;
    private readonly ILogger<HealthCheckService> _logger = logger;

    private readonly string _healthCheckFilePath = Path.Combine(fileManager.GetDataPath(), "healthcheck.json");
    private readonly SemaphoreSlim _semaphoreSlim = new(1, 1);

    public void Dispose() => _semaphoreSlim.Dispose();

    public IHealthToken GetHealthToken(string service) => new HealthToken(service, this);

    public async Task<Result> InitialiseAsync(CancellationToken cancellationToken)
    {
        try
        {
            if (_options.ServicesToRegister.Length > 0)
            {
                var healthChecks = _options.ServicesToRegister.ToDictionary<string, string, HealthCheckEntry?>(x => x, x => null);
                await _fileManager.SerialiseToFileAsync(healthChecks, _healthCheckFilePath, cancellationToken);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to initialise health checks.");
            return Result.Fail($"Failed to initialise health checks: {ex.Message}");
        }

        return Result.Ok();
    }

    public async Task<HealthCheckResult> CheckHealthAsync(CancellationToken cancellationToken)
    {
        var healthChecks = await _fileManager.DeserialiseFromFileAsync<HealthChecks>(_healthCheckFilePath, cancellationToken);
        if (healthChecks is null)
        {
            return new(HealthStatus.Unhealthy, "No health checks found.");
        }

        foreach (var (service, healthCheck) in healthChecks)
        {
            if (healthCheck is null)
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

    private async Task Unregister(string service, CancellationToken cancellationToken)
    {
        await _semaphoreSlim.WaitAsync(cancellationToken);

        try
        {
            var healthChecks = await _fileManager.DeserialiseFromFileAsync<HealthChecks>(_healthCheckFilePath, cancellationToken) ?? [];
            healthChecks.Remove(service);

            _logger.LogDebug("Unregistering '{Service}' from health checks.", service);
            await _fileManager.SerialiseToFileAsync(healthChecks, _healthCheckFilePath, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to unregister '{Service}' from health checks.", service);
        }
        finally
        {
            _semaphoreSlim.Release();
        }
    }

    private async Task SetHealth(string service, HealthStatus status, CancellationToken cancellationToken)
    {
        await _semaphoreSlim.WaitAsync(cancellationToken);

        try
        {
            var healthChecks = await _fileManager.DeserialiseFromFileAsync<HealthChecks>(_healthCheckFilePath, cancellationToken) ?? [];
            if (!healthChecks.ContainsKey(service))
            {
                throw new InvalidOperationException($"Service '{service}' is not registered.");
            }

            healthChecks[service] = new(DateTime.UtcNow, status);

            _logger.LogDebug("Persisting health status '{HealthStatus}' for '{Service}'.", status, service);
            await SerialiseWithRetryAsync(healthChecks, cancellationToken);
        }
        catch (InvalidOperationException)
        {
            throw;
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

    private async Task SerialiseWithRetryAsync(HealthChecks healthChecks, CancellationToken cancellationToken)
    {
        const int maxAttempts = 5;
        var delay = TimeSpan.FromMilliseconds(200);

        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            try
            {
                await _fileManager.SerialiseToFileAsync(healthChecks, _healthCheckFilePath, cancellationToken);
                return;
            }
            catch (IOException ex) when (attempt < maxAttempts)
            {
                _logger.LogWarning(
                    ex,
                    "healthcheck.json is locked by another process (attempt {Attempt}/{MaxAttempts}), retrying in {Delay}ms.",
                    attempt,
                    maxAttempts,
                    delay.TotalMilliseconds);
                await Task.Delay(delay, cancellationToken);
                delay *= 2;
            }
        }
    }

    private sealed class HealthToken(string service, HealthCheckService healthCheckService) : IHealthToken
    {
        private readonly string _service = service;
        private readonly HealthCheckService _healthCheckService = healthCheckService;

        public Task HealthyAsync(CancellationToken cancellationToken) =>
            _healthCheckService.SetHealth(_service, HealthStatus.Healthy, cancellationToken);

        public Task UnhealthyAsync(CancellationToken cancellationToken) =>
            _healthCheckService.SetHealth(_service, HealthStatus.Unhealthy, cancellationToken);

        public Task UnregisterAsync(CancellationToken cancellationToken) =>
            _healthCheckService.Unregister(_service, cancellationToken);
    }
}
