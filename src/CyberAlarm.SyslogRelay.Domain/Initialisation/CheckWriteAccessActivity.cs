using CyberAlarm.SyslogRelay.Domain.Services;
using FluentResults;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Initialisation;

internal sealed class CheckWriteAccessActivity(
    IFileManager fileManager,
    IPlatformService platformService,
    ILogger<CheckWriteAccessActivity> logger) : IStartupActivity
{
    private readonly IFileManager _fileManager = fileManager;
    private readonly IPlatformService _platformService = platformService;
    private readonly ILogger<CheckWriteAccessActivity> _logger = logger;

    public Task<Result> RunAsync(CancellationToken cancellationToken) => Task.FromResult(Run());

    private Result Run()
    {
        _logger.LogInformation("Check platform support.");
        if (!IsPlatformSupported())
        {
            return Result.Fail("Current platform is not supported.");
        }

        _logger.LogInformation("Check write access.");
        var dataPath = _fileManager.GetDataPath();
        if (!IsVolumeWritable(dataPath))
        {
            return Result.Fail($"Data volume '{dataPath}' is not writable.");
        }

        return Result.Ok();
    }

    private bool IsPlatformSupported() =>
        _platformService.GetPlatformType() != PlatformType.NotSupported;

    private bool IsVolumeWritable(string volumePath)
    {
        var filePath = Path.Combine(volumePath, $"{Guid.NewGuid()}.tmp");
        return _fileManager.CanWriteFile(filePath);
    }
}
