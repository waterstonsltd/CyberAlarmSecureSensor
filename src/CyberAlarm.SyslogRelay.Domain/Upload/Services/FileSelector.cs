using CyberAlarm.SyslogRelay.Domain.Services;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Upload.Services;

/// <summary>
/// FileSelector service.
/// Selects Syslog event files from the logs folder and moves them to the processing folder.
/// </summary>
/// <param name="fileManager">Used for file IO.</param>
/// <param name="logger">Used for logging.</param>
internal sealed class FileSelector(
    IFileManager fileManager,
    ILogger<FileSelector> logger) : IFileSelector
{
    private readonly IFileManager _fileManager = fileManager;
    private readonly ILogger<FileSelector> _logger = logger;

    public async Task SelectFilesAsync(CancellationToken cancellationToken)
    {
        var inputFolder = _fileManager.GetLogsFolder();
        var outputFolder = _fileManager.GetProcessingFolder();
        var inputFiles = _fileManager.ListFilesInDirectory(inputFolder);

        _logger.LogInformation(
            "Moving {FileCount} file(s) from {InputFolder} to {ProcessingFolder}",
            inputFiles.Count(),
            inputFolder,
            outputFolder);
        foreach (var inputFile in inputFiles)
        {
            var destinationFilePath = Path.Combine(outputFolder, Path.GetFileName(inputFile));
            try
            {
                _fileManager.Move(inputFile, destinationFilePath);
            }
            catch (IOException ex)
            {
                _logger.LogError(ex, "Error moving file '{File}' to processing folder: {Message}", inputFile, ex.Message);
            }
        }
    }
}
