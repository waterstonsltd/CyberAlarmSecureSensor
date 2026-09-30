using System.Diagnostics;
using CyberAlarm.SyslogRelay.Domain.Services;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Upload.Services;

/// <summary>
/// FileSelector service.
/// Selects Syslog event files from the logs folder and moves them to the processing folder.
/// </summary>
/// <param name="fileManager">Used for file IO.</param>
/// <param name="uploadMetrics">Used for recording metrics.</param>
/// <param name="logger">Used for logging.</param>
internal sealed class FileSelector(
    IFileManager fileManager,
    UploadMetrics uploadMetrics,
    ILogger<FileSelector> logger) : IFileSelector
{
    private readonly IFileManager _fileManager = fileManager;
    private readonly UploadMetrics _uploadMetrics = uploadMetrics;
    private readonly ILogger<FileSelector> _logger = logger;

    public async Task SelectFilesAsync(CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var inputFolder = _fileManager.GetLogsFolder();
        var outputFolder = _fileManager.GetProcessingFolder();
        var inputFiles = _fileManager.ListFilesInDirectory(inputFolder).ToList();

        _logger.LogInformation(
            "Moving {FileCount} file(s) from {InputFolder} to {ProcessingFolder}",
            inputFiles.Count,
            inputFolder,
            outputFolder);

        long movedCount = 0;
        foreach (var inputFile in inputFiles)
        {
            var destinationFilePath = Path.Combine(outputFolder, Path.GetFileName(inputFile));
            try
            {
                _fileManager.Move(inputFile, destinationFilePath);
                movedCount++;
            }
            catch (IOException ex)
            {
                _logger.LogError(ex, "Error moving file '{File}' to processing folder: {Message}", inputFile, ex.Message);
            }
        }

        stopwatch.Stop();
        _uploadMetrics.SelectorFilesSelected.Add(movedCount);
        _uploadMetrics.SelectorDuration.Record(stopwatch.Elapsed.TotalMilliseconds);
    }
}
