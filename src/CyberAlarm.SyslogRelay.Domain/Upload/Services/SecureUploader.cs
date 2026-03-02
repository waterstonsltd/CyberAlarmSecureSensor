using System.Diagnostics;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Domain.State;
using CyberAlarm.SyslogRelay.Domain.Status;
using CyberAlarm.SyslogRelay.Domain.Upload.Infrastructure;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Polly;
using Polly.Retry;
using Renci.SshNet.Common;

namespace CyberAlarm.SyslogRelay.Domain.Upload.Services;

/// <summary>
/// SecureUploader service.
/// Uploads bundled files from the upload folder to secure FTP storage.
/// </summary>
/// <param name="fileManager">Used for file IO.</param>
/// <param name="rsaKeyProvider">Provides private RSA key for SFTP.</param>
/// <param name="statusService">Used to retrieve the host name for the required "bucket" for the account.</param>
/// <param name="secureFtpClientFactory">Provides a secure FTP client.</param>
/// <param name="options">Provides the user's connection details.</param>
/// <param name="logger">Used for logging.</param>
internal class SecureUploader(
    IApplicationManager applicationManager,
    IFileManager fileManager,
    IRsaKeyProvider rsaKeyProvider,
    IStateService stateService,
    IStatusService statusService,
    ISecureFtpClientFactory secureFtpClientFactory,
    IOptions<RelayOptions> options,
    ILogger<SecureUploader> logger) : ISecureUploader
{
    private const string _storageAccountDomain = "blob.core.windows.net";
    private readonly IApplicationManager _applicationManager = applicationManager;
    private readonly IFileManager _fileManager = fileManager;
    private readonly IRsaKeyProvider _rsaKeyProvider = rsaKeyProvider;
    private readonly IStateService _stateService = stateService;
    private readonly IStatusService _statusService = statusService;
    private readonly RelayOptions _relayOptions = options.Value;
    private readonly ILogger<SecureUploader> _logger = logger;
    private readonly AsyncRetryPolicy _retryPolicy = Policy
            .Handle<SshException>()
            .Or<SshConnectionException>()
            .WaitAndRetryAsync(
                retryCount: 5,
                sleepDurationProvider: attempt => TimeSpan.FromSeconds(attempt));

    public async Task UploadFilesAsync(CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();

        var inputFolder = _fileManager.GetUploadFolder();
        var filesToUpload = _fileManager.ListFilesInDirectory(inputFolder).ToList();
        var totalFiles = filesToUpload.Count;

        if (totalFiles == 0)
        {
            _logger.LogInformation("No files to upload");
            return;
        }

        _logger.LogInformation("Found {TotalFiles} files to upload", totalFiles);

        var bucket = _relayOptions.Bucket;
        var status = await _statusService.GetStatusAsync(cancellationToken);
        var storageAccountName = status.StorageAccounts[bucket];
        var targetServer = $"{storageAccountName}.{_storageAccountDomain}";
        var userName = $"{storageAccountName}.{_relayOptions.UserName}";
        var privateKey = await _rsaKeyProvider.GetPrivateKeyPem(cancellationToken);
        using var secureFtpClient = secureFtpClientFactory.Create(targetServer, userName, privateKey);

        int uploadedCount = 0;
        int failedCount = 0;
        const int progressInterval = 100; // Log progress every 100 files

        foreach (var file in filesToUpload)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                await _retryPolicy.ExecuteAsync(async () =>
                {
                    if (!secureFtpClient.IsConnected)
                    {
                        secureFtpClient.Connect();
                    }

                    var targetFilePath = GetTargetFilePath(file, inputFolder);
                    await EnsureDirectoryPathExists(secureFtpClient, targetFilePath);

                    using var stream = _fileManager.OpenStreamFromFile(file, cancellationToken);
                    await secureFtpClient.UploadFileAsync(stream, targetFilePath, cancellationToken);
                });

                _fileManager.Delete(file);
                uploadedCount++;
                _logger.LogInformation("{FileName} successfully uploaded", file);
            }
            catch (Exception ex) when (ex is SshAuthenticationException or SshConnectionException)
            {
                _logger.LogCritical(ex, "Critical error while connecting to the server. Stopping application.");
                failedCount++;

                await StopApplication(cancellationToken);
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error uploading {FileName}", file);
                failedCount++;
            }

            // Log progress at intervals
            if ((uploadedCount + failedCount) % progressInterval == 0)
            {
                _logger.LogInformation(
                    "Upload progress: {Uploaded}/{Total} files uploaded ({PercentComplete:F1}%), {Failed} failed, elapsed time: {Elapsed}",
                    uploadedCount + failedCount,
                    totalFiles,
                    ((uploadedCount + failedCount) / (double)totalFiles) * 100,
                    failedCount,
                    stopwatch.Elapsed.ToString(@"hh\:mm\:ss"));
            }
        }

        if (secureFtpClient.IsConnected)
        {
            secureFtpClient.Disconnect();
        }

        stopwatch.Stop();
        _logger.LogInformation(
            "Upload complete: {Uploaded} files uploaded successfully, {Failed} failed out of {Total} total in {Elapsed}",
            uploadedCount,
            failedCount,
            totalFiles,
            stopwatch.Elapsed.ToString(@"hh\:mm\:ss"));
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

    private static async Task EnsureDirectoryPathExists(ISecureFtpClient secureFtpClient, string path)
    {
        var lastSeparatorIndex = path.LastIndexOf('/');
        var directoryPath = lastSeparatorIndex < 0 ? string.Empty : path[..lastSeparatorIndex];
        if (!string.IsNullOrEmpty(directoryPath))
        {
            await EnsureDirectoryPathExists(secureFtpClient, directoryPath);
        }

        if (!path.EndsWith(".calr") && !secureFtpClient.Exists(path))
        {
            await secureFtpClient.CreateDirectoryAsync(path);
        }
    }

    private async Task StopApplication(CancellationToken cancellationToken)
    {
        await _stateService.UpdateStateAsync(
            state => state with { IsUploadBlocked = true },
            cancellationToken);

        _applicationManager.StopApplication();
    }
}
