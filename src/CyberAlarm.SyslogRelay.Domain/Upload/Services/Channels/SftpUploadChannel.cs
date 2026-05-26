using System.Net.Sockets;
using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Domain.State;
using CyberAlarm.SyslogRelay.Domain.Upload.Infrastructure;
using Microsoft.Extensions.Logging;
using Polly;
using Polly.Retry;
using Renci.SshNet.Common;

namespace CyberAlarm.SyslogRelay.Domain.Upload.Services.Channels;

internal sealed class SftpUploadChannel(
    ISecureFtpClient secureFtpClient,
    IFileManager fileManager,
    IApplicationManager applicationManager,
    IStateService stateService,
    UploadMetrics uploadMetrics,
    ILogger logger)
    : IUploadChannel
{
    private readonly AsyncRetryPolicy _retryPolicy = Policy
        .Handle<SshException>(ex => ex is not SshOperationTimeoutException)
        .Or<SshConnectionException>()
        .WaitAndRetryAsync(
            retryCount: 5,
            sleepDurationProvider: attempt => TimeSpan.FromSeconds(attempt));

    public async Task<UploadFileOutcome> UploadFileAsync(string localFile, string targetPath, CancellationToken cancellationToken)
    {
        try
        {
            await _retryPolicy.ExecuteAsync(async () =>
            {
                if (!secureFtpClient.IsConnected)
                {
                    secureFtpClient.Connect();
                }

                await EnsureDirectoryPathExists(secureFtpClient, targetPath);
                using var stream = fileManager.OpenStreamFromFile(localFile, cancellationToken);
                await secureFtpClient.UploadFileAsync(stream, targetPath, cancellationToken);
            });

            fileManager.Delete(localFile);
            uploadMetrics.FilesUploaded.Add(1);
            logger.LogInformation("{FileName} successfully uploaded", localFile);
            return UploadFileOutcome.Uploaded;
        }
        catch (Exception ex) when (ex is SshAuthenticationException or SshConnectionException)
        {
            logger.LogCritical(ex, "Critical error while connecting to the server. Stopping application.");
            uploadMetrics.FilesFailed.Add(1);
            await StopApplicationAsync(cancellationToken);
            return UploadFileOutcome.FailedStop;
        }
        catch (SshOperationTimeoutException ex)
        {
            logger.LogWarning(
                ex,
                "SFTP connection to {TargetServer} timed out (TCP port 22 may be blocked). Signalling fallback to next upload channel.",
                secureFtpClient);
            uploadMetrics.FilesFailed.Add(1);
            return UploadFileOutcome.TryNextChannel;
        }
        catch (SocketException ex)
        {
            logger.LogWarning(
                ex,
                "SFTP TCP connection to {TargetServer} failed ({SocketError}). Signalling fallback to next upload channel.",
                secureFtpClient,
                ex.SocketErrorCode);
            uploadMetrics.FilesFailed.Add(1);
            return UploadFileOutcome.TryNextChannel;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error uploading {FileName}", localFile);
            uploadMetrics.FilesFailed.Add(1);
            return UploadFileOutcome.Failed;
        }
    }

    public ValueTask DisposeAsync()
    {
        if (secureFtpClient.IsConnected)
        {
            secureFtpClient.Disconnect();
        }

        secureFtpClient.Dispose();
        return ValueTask.CompletedTask;
    }

    private async Task StopApplicationAsync(CancellationToken cancellationToken)
    {
        await stateService.UpdateStateAsync(
            state => state with { IsUploadBlocked = true },
            cancellationToken);

        applicationManager.StopApplication();
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
}
