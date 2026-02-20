using System.Diagnostics;
using System.Text.Json;
using CyberAlarm.EventBundler.Services;
using CyberAlarm.SyslogRelay.Common.EventBundler.Models;
using CyberAlarm.SyslogRelay.Common.EventBundler.Settings;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Domain.Status;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Upload.Services;

/// <summary>
/// FileBundler service.
/// Reads a set of event log files in the source group folder.
/// Encrypts, compresses and signs each file
/// before bundling their contents ready for upload.
/// Writes the bundled files to the upload folder.
/// </summary>
/// <param name="fileManager">Used for file IO.</param>
/// <param name="eventBundlerService">Handles all encryption, compression, signing and bundling.</param>
/// <param name="platformService">Provides info on the currently running platform.</param>
/// <param name="statusService">Provides server public key.</param>
/// <param name="rsaKeyProvider">Provides private RSA key.</param>
/// <param name="relayOptions">Provides info used in bundle creation.</param>
/// <param name="logger">Used for logging.</param>
internal sealed class FileBundler(
    IFileManager fileManager,
    IEventBundlerService eventBundlerService,
    IPlatformService platformService,
    IStatusService statusService,
    IRsaKeyProvider rsaKeyProvider,
    IOptions<RelayOptions> relayOptions,
    ILogger<FileBundler> logger) : IFileBundler
{
    private readonly IFileManager _fileManager = fileManager;
    private readonly IEventBundlerService _eventBundlerService = eventBundlerService;
    private readonly IPlatformService _platformService = platformService;
    private readonly IStatusService _statusService = statusService;
    private readonly IRsaKeyProvider _rsaKeyProvider = rsaKeyProvider;
    private readonly RelayOptions _relayOptions = relayOptions.Value;
    private readonly ILogger<FileBundler> _logger = logger;

    public async Task BundleFilesAsync(CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var inputFolder = _fileManager.GetSourceGroupFolder();
        var outputFolder = _fileManager.GetUploadFolder();
        var failedFolder = _fileManager.GetFailedFolder();
        var temporaryFolder = _fileManager.GetTemporaryFolder();
        var buildVersion = _relayOptions.BuildVersion;
        var relayId = _relayOptions.RelayId;
        var platform = _platformService.GetPlatform();
        var privateKey = await _rsaKeyProvider.GetPrivateKeyDer(cancellationToken);
        var status = await _statusService.GetStatusAsync(cancellationToken);
        var publicKey = _rsaKeyProvider.GetPublicKeyDerBytes(status.ServerPublicKey);

        var allFiles = _fileManager.ListFilesInDirectory(inputFolder).ToList();
        var totalFiles = allFiles.Count;
        _logger.LogInformation("Found {TotalFiles} files to bundle", totalFiles);

        int processedCount = 0;
        int failedCount = 0;
        const int progressInterval = 1; // Log progress every file

        foreach (var file in allFiles)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var fileName = Path.GetFileName(file);
            try
            {
                long inputSize = _fileManager.GetFileSize(file);

                string temporaryBufferFile = string.Empty;
                string temporaryOutputFile = string.Empty;

                try
                {
                    temporaryBufferFile = Path.Combine(temporaryFolder, $"{Guid.NewGuid()}.tmp");
                    temporaryOutputFile = Path.Combine(temporaryFolder, $"{Guid.NewGuid()}.tmp");

                    using Stream data = _fileManager.OpenStreamFromFile(file, cancellationToken);
                    using Stream temporaryStream = _fileManager.OpenWriteStreamForFile(temporaryBufferFile, cancellationToken);
                    using Stream outputStream = _fileManager.OpenWriteStreamForFile(temporaryOutputFile, cancellationToken);
                    await _eventBundlerService.BundleAsync(
                        outputStream,
                        data,
                        temporaryStream,
                        relayId,
                        buildVersion,
                        new Common.EventBundler.Models.Platform(platform.Os, platform.Runtime, platform.Architecture),
                        privateKey,
                        publicKey,
                        new BundleOptions(),
                        cancellationToken);

                    data.Close();
                    temporaryStream.Close();
                    outputStream.Close();

                    var outputFile = GetTargetPath(file, inputFolder, outputFolder);
                    _fileManager.Move(temporaryOutputFile, outputFile);
                    var outputSize = _fileManager.GetFileSize(outputFile);
                    var compressionRatio = (1 - (outputSize / (double)inputSize)) * 100;

                    _logger.LogDebug(
                        "Bundled '{FileName}': {InputSize:N0} bytes -> {OutputSize:N0} bytes ({CompressionRatio:F1}% reduction)",
                        fileName,
                        inputSize,
                        outputSize,
                        compressionRatio);

                    _fileManager.Delete(file);
                    processedCount++;
                }
                finally
                {
                    if (_fileManager.Exists(temporaryBufferFile))
                    {
                        _fileManager.Delete(temporaryBufferFile);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to bundle file '{File}'", fileName);
                _fileManager.Move(file, Path.Combine(failedFolder, fileName));
                failedCount++;
            }

            // Log progress at intervals
            if ((processedCount + failedCount) % progressInterval == 0)
            {
                _logger.LogInformation(
                    "Bundling progress: {Processed}/{Total} files processed ({PercentComplete:F1}%), {Failed} failed, elapsed time: {Elapsed}",
                    processedCount + failedCount,
                    totalFiles,
                    ((processedCount + failedCount) / (double)totalFiles) * 100,
                    failedCount,
                    stopwatch.Elapsed.ToString(@"hh\:mm\:ss"));
            }
        }

        stopwatch.Stop();
        _logger.LogInformation(
            "Bundling complete: {Processed} files bundled successfully, {Failed} failed out of {Total} total in {Elapsed}",
            processedCount,
            failedCount,
            totalFiles,
            stopwatch.Elapsed.ToString(@"hh\:mm\:ss"));
    }

    private static string GetTargetPath(string sourceFilePath, string inputFolder, string outputFolder)
    {
        var targetPath = sourceFilePath.Replace(inputFolder, outputFolder);
        return Path.ChangeExtension(targetPath, ".calr");
    }
}
