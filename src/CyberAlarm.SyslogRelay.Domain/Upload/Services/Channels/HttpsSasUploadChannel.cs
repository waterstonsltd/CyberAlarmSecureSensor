using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Domain.State;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Upload.Services.Channels;

/// <summary>
/// Uploads files to Azure Blob Storage via a SAS token obtained from the relay API.
/// The SAS token is fetched lazily on the first upload attempt and reused for subsequent uploads.
/// </summary>
internal sealed class HttpsSasUploadChannel(
    IHttpClientFactory httpClientFactory,
    UploadContext context,
    IFileManager fileManager,
    IApplicationManager applicationManager,
    IStateService stateService,
    UploadMetrics uploadMetrics,
    ILogger logger)
    : IUploadChannel
{
    private static readonly TimeSpan TokenExpiryBuffer = TimeSpan.FromSeconds(30);

    private UploadTokenResponse? _token;

    public async Task<UploadFileOutcome> UploadFileAsync(string localFile, string targetPath, CancellationToken cancellationToken)
    {
        if (_token is null || DateTimeOffset.UtcNow >= _token.ExpiresAt - TokenExpiryBuffer)
        {
            _token = await FetchTokenAsync(cancellationToken);

            if (_token is null)
            {
                return UploadFileOutcome.Blocked;
            }
        }

        return await UploadBlobAsync(localFile, targetPath, cancellationToken);
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    private async Task<UploadTokenResponse?> FetchTokenAsync(CancellationToken cancellationToken)
    {
        try
        {
            var relayId = context.RelayOptions.RelayId;
            var jwt = BuildUploadJwt(relayId, context.PrivateKeyPem);
            var url = $"{context.RelayOptions.ApiBaseUrl}/api/v1/syslogrelay/{Uri.EscapeDataString(relayId)}/upload-token";

            var httpClient = httpClientFactory.CreateClient(nameof(SecureUploader));
            using var response = await httpClient.PostAsJsonAsync(url, new { token = jwt }, cancellationToken);

            if (response.StatusCode == HttpStatusCode.Forbidden)
            {
                logger.LogCritical(
                    "HTTPS upload token request returned 403 Forbidden. The relay is not recognised or the JWT was rejected. Stopping application.");
                await StopApplicationAsync(cancellationToken);
                return null;
            }

            if (!response.IsSuccessStatusCode)
            {
                logger.LogError(
                    "Failed to obtain HTTPS upload token: HTTP {StatusCode}.",
                    (int)response.StatusCode);
                return null;
            }

            var token = await response.Content.ReadFromJsonAsync<UploadTokenResponse>(cancellationToken);

            if (token?.SasUri is null)
            {
                logger.LogError("HTTPS upload token response did not contain a valid SAS URI.");
                return null;
            }

            return token;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "Failed to obtain HTTPS upload token.");
            return null;
        }
    }

    private async Task<UploadFileOutcome> UploadBlobAsync(string localFile, string targetPath, CancellationToken cancellationToken)
    {
        try
        {
            var sasUriParsed = new Uri(_token!.SasUri!);
            var blobUrl = $"{sasUriParsed.Scheme}://{sasUriParsed.Host}{sasUriParsed.AbsolutePath}/{targetPath}{sasUriParsed.Query}";

            var fileBytes = await fileManager.LoadFromFileAsync(localFile, cancellationToken)
                ?? throw new InvalidOperationException($"File '{localFile}' could not be read.");

            using var content = new ByteArrayContent(fileBytes);
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");

            using var request = new HttpRequestMessage(HttpMethod.Put, blobUrl);
            request.Headers.TryAddWithoutValidation("x-ms-blob-type", "BlockBlob");
            request.Content = content;

            var httpClient = httpClientFactory.CreateClient(nameof(SecureUploader));
            using var response = await httpClient.SendAsync(request, cancellationToken);

            if (response.StatusCode == HttpStatusCode.Forbidden)
            {
                logger.LogCritical(
                    "SAS token rejected (403 Forbidden) while uploading {FileName}. The token may have expired. Stopping application.",
                    localFile);
                uploadMetrics.FilesFailed.Add(1);
                await StopApplicationAsync(cancellationToken);
                return UploadFileOutcome.FailedStop;
            }

            if (response.StatusCode != HttpStatusCode.Created)
            {
                logger.LogError("Error uploading {FileName}: HTTP {StatusCode}", localFile, (int)response.StatusCode);
                uploadMetrics.FilesFailed.Add(1);
                return UploadFileOutcome.Failed;
            }

            fileManager.Delete(localFile);
            uploadMetrics.FilesUploaded.Add(1);
            logger.LogInformation("{FileName} successfully uploaded", localFile);
            return UploadFileOutcome.Uploaded;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "Error uploading {FileName}", localFile);
            uploadMetrics.FilesFailed.Add(1);
            return UploadFileOutcome.Failed;
        }
    }

    private async Task StopApplicationAsync(CancellationToken cancellationToken)
    {
        await stateService.UpdateStateAsync(
            state => state with { IsUploadBlocked = true },
            cancellationToken);

        applicationManager.StopApplication();
    }

    private static string BuildUploadJwt(string relayId, string privateKeyPem)
    {
        var header = Base64UrlEncode(Encoding.UTF8.GetBytes("""{"alg":"RS256","typ":"JWT"}"""));

        var now = DateTimeOffset.UtcNow;
        var iat = now.ToUnixTimeSeconds();
        var exp = iat + 540;

        var payloadJson = JsonSerializer.Serialize(new UploadJwtPayload(relayId, relayId, iat, exp));
        var payload = Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));

        var headerAndPayload = $"{header}.{payload}";

        using var rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyPem);
        var signature = Base64UrlEncode(
            rsa.SignData(
                Encoding.UTF8.GetBytes(headerAndPayload),
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1));

        return $"{headerAndPayload}.{signature}";
    }

    private static string Base64UrlEncode(byte[] data) =>
        Convert.ToBase64String(data)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private sealed record UploadJwtPayload(
        [property: JsonPropertyName("sub")] string Sub,
        [property: JsonPropertyName("aud")] string Aud,
        [property: JsonPropertyName("iat")] long Iat,
        [property: JsonPropertyName("exp")] long Exp);

    private sealed record UploadTokenResponse(
        [property: JsonPropertyName("sasUri")] string? SasUri,
        [property: JsonPropertyName("expiresAt")] DateTimeOffset ExpiresAt);
}
