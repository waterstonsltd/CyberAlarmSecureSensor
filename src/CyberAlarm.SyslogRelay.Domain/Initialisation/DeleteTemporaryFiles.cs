using System;
using System.Collections.Generic;
using System.Text;
using CyberAlarm.SyslogRelay.Domain.Services;
using FluentResults;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Initialisation;

public class DeleteTemporaryFiles : IStartupActivity
{
    private readonly IFileManager _fileManager;
    private readonly ILogger<DeleteTemporaryFiles> _logger;

    public DeleteTemporaryFiles(IFileManager fileManager, ILogger<DeleteTemporaryFiles> logger)
    {
        _fileManager = fileManager;
        _logger = logger;
    }

    public Task<Result> RunAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Starting cleanup of temporary files");

        string temporaryFilesFolder = _fileManager.GetTemporaryFolder();
        _logger.LogDebug("Temporary files folder: {TemporaryFolder}", temporaryFilesFolder);

        var files = _fileManager.ListFilesInDirectory(temporaryFilesFolder);
        var fileCount = files.Count();

        _logger.LogInformation("Found {FileCount} temporary file(s) to delete", fileCount);

        var deletedCount = 0;
        foreach (var file in files)
        {
            try
            {
                _fileManager.Delete(file);
                deletedCount++;
                _logger.LogDebug("Deleted temporary file: {FilePath}", file);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to delete temporary file: {FilePath}", file);
            }
        }

        _logger.LogInformation("Completed temporary files cleanup. Deleted {DeletedCount} of {TotalCount} file(s)", deletedCount, fileCount);

        return Task.FromResult(Result.Ok());
    }
}
