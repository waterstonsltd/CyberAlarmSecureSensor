using System.Diagnostics;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Domain.Status;
using CyberAlarm.SyslogRelay.Domain.Upload.Services.Channels;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Upload.Services;

/// <summary>
/// SecureUploader service.
/// Uploads bundled files from the upload folder to secure storage.
/// Tries each registered upload channel in order; if one signals <see cref="UploadAttemptResult.TryNextChannel"/>,
/// the next channel in the list is used for the remaining files.
/// </summary>
/// <param name="fileManager">Used for file IO.</param>
/// <param name="rsaKeyProvider">Provides private RSA key for authentication and JWT signing.</param>
/// <param name="statusService">Used to retrieve the host name for the required "bucket" for the account.</param>
/// <param name="channelFactories">Ordered list of upload channel factories tried in sequence.</param>
/// <param name="options">Provides the user's connection details.</param>
/// <param name="logger">Used for logging.</param>
internal class SecureUploader(
    IFileManager fileManager,
    IRsaKeyProvider rsaKeyProvider,
    IStatusService statusService,
    IEnumerable<IUploadChannelFactory> channelFactories,
    IOptions<RelayOptions> options,
    UploadMetrics uploadMetrics,
    ILogger<SecureUploader> logger) : ISecureUploader
{
    private readonly IFileManager _fileManager = fileManager;
    private readonly IRsaKeyProvider _rsaKeyProvider = rsaKeyProvider;
    private readonly IStatusService _statusService = statusService;
    private readonly List<IUploadChannelFactory> _channelFactories = channelFactories.ToList();
    private readonly RelayOptions _relayOptions = options.Value;
    private readonly UploadMetrics _uploadMetrics = uploadMetrics;
    private readonly ILogger<SecureUploader> _logger = logger;

    public async Task<UploadResult> UploadFilesAsync(CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();

        var inputFolder = _fileManager.GetUploadFolder();
        var filesToUpload = _fileManager.ListFilesInDirectory(inputFolder).ToList();
        var totalFiles = filesToUpload.Count;

        if (totalFiles == 0)
        {
            _logger.LogInformation("No files to upload");
            return UploadResult.Empty;
        }

        _logger.LogInformation("Found {TotalFiles} files to upload", totalFiles);

        var status = await _statusService.GetStatusAsync(cancellationToken);
        var storageAccountName = status.StorageAccounts[_relayOptions.Bucket];

        if (!IsValidStorageAccountName(storageAccountName))
        {
            _logger.LogError("Storage account name '{StorageAccountName}' contains invalid characters.", storageAccountName);
            return UploadResult.Empty;
        }

        var privateKey = await _rsaKeyProvider.GetPrivateKeyPem(cancellationToken);
        var context = new UploadContext(storageAccountName, privateKey, status, _relayOptions);

        int uploadedCount = 0;
        int failedCount = 0;
        const int progressInterval = 100; // Log progress every 100 files

        int fileIndex = 0;
        int factoryIndex = 0;
        IUploadChannel? activeChannel = null;
        try
        {
            while (fileIndex < filesToUpload.Count)
            {
                cancellationToken.ThrowIfCancellationRequested();

                activeChannel ??= _channelFactories[factoryIndex].Create(context);

                var file = filesToUpload[fileIndex];
                var targetPath = GetTargetFilePath(file, inputFolder);
                var outcome = await activeChannel.UploadFileAsync(file, targetPath, cancellationToken);

                if (outcome == UploadFileOutcome.TryNextChannel)
                {
                    await activeChannel.DisposeAsync();
                    activeChannel = null;
                    factoryIndex++;

                    if (factoryIndex >= _channelFactories.Count)
                    {
                        _logger.LogError("All upload channels exhausted. Aborting upload cycle.");
                        break;
                    }

                    _logger.LogWarning(
                        "Upload channel signalled fallback. Switching to next channel ({Remaining} file(s) remaining).",
                        filesToUpload.Count - fileIndex);

                    continue; // Retry the current file with the next channel
                }

                switch (outcome)
                {
                    case UploadFileOutcome.Uploaded:
                        uploadedCount++;
                        break;
                    case UploadFileOutcome.Failed:
                        failedCount++;
                        break;
                    case UploadFileOutcome.FailedStop:
                        failedCount++;
                        break;
                }

                if (outcome is UploadFileOutcome.FailedStop or UploadFileOutcome.Blocked)
                {
                    break;
                }

                // Log progress at intervals
                LogProgressIfNeeded(uploadedCount, failedCount, totalFiles, progressInterval, stopwatch.Elapsed);

                fileIndex++;
            }
        }
        finally
        {
            if (activeChannel is not null)
            {
                await activeChannel.DisposeAsync();
            }
        }

        stopwatch.Stop();
        _uploadMetrics.CycleDuration.Record(stopwatch.Elapsed.TotalMilliseconds);
        _logger.LogInformation(
            "Upload complete: {Uploaded} files uploaded successfully, {Failed} failed out of {Total} total in {Elapsed}",
            uploadedCount,
            failedCount,
            totalFiles,
            stopwatch.Elapsed.ToString(@"hh\:mm\:ss"));

        return new UploadResult(uploadedCount, failedCount);
    }

    private void LogProgressIfNeeded(int uploaded, int failed, int total, int interval, TimeSpan elapsed)
    {
        if ((uploaded + failed) % interval == 0)
        {
            _logger.LogInformation(
                "Upload progress: {Uploaded}/{Total} files uploaded ({PercentComplete:F1}%), {Failed} failed, elapsed time: {Elapsed}",
                uploaded + failed,
                total,
                ((uploaded + failed) / (double)total) * 100,
                failed,
                elapsed.ToString(@"hh\:mm\:ss"));
        }
    }

    private static string GetTargetFilePath(string inputFilePath, string inputFolder)
    {
        // Note that SFTP always uses '/' as the directory separator regardless of the OS we're running
        return inputFilePath
            .Replace(inputFolder, string.Empty)
            .Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar)
            .Replace(Path.DirectorySeparatorChar, '/')
            .Trim('/');
    }

    /// <summary>
    /// Azure storage account names must be 3-24 lowercase alphanumeric characters only.
    /// Validating prevents host-injection attacks via a compromised server-supplied status response.
    /// </summary>
    private static bool IsValidStorageAccountName(string? name) =>
        !string.IsNullOrEmpty(name) &&
        name.Length >= 3 &&
        name.Length <= 24 &&
        name.All(c => char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c));
}
