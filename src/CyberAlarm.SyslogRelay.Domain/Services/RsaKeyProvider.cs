using System.Security.Cryptography;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Services;

internal sealed class RsaKeyProvider(
    IFileManager fileManager,
    IOptions<RelayOptions> options,
    ILogger<RsaKeyProvider> logger) : IRsaKeyProvider
{
    private readonly IFileManager _fileManager = fileManager;
    private readonly RelayOptions _options = options.Value;
    private readonly ILogger<RsaKeyProvider> _logger = logger;

    private readonly string _keyFilePath = Path.Combine(fileManager.GetDataPath(), "key.der");

    private RSA? _rsa;

    public bool KeysExist() => _fileManager.Exists(_keyFilePath);

    public async Task<string> GetPublicKeyPem(CancellationToken cancellationToken)
    {
        var rsa = await GetRSA(cancellationToken);
        return rsa.ExportRSAPublicKeyPem();
    }

    public async Task<string> GetPrivateKeyPem(CancellationToken cancellationToken)
    {
        var rsa = await GetRSA(cancellationToken);
        return rsa.ExportRSAPrivateKeyPem();
    }

    public async Task<byte[]> GetPublicKeyDer(CancellationToken cancellationToken)
    {
        var rsa = await GetRSA(cancellationToken);
        return rsa.ExportRSAPublicKey();
    }

    public async Task<byte[]> GetPrivateKeyDer(CancellationToken cancellationToken)
    {
        var rsa = await GetRSA(cancellationToken);
        return rsa.ExportRSAPrivateKey();
    }

    public byte[] GetPublicKeyDerBytes(string publicKeyPem)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(publicKeyPem);
        var bytes = rsa.ExportRSAPublicKey();
        return bytes;
    }

    private async Task<RSA> GetRSA(CancellationToken cancellationToken)
    {
        if (_rsa != null)
        {
            return _rsa;
        }

        _logger.LogDebug("Loading RSA private key from {KeyFilePath}", _keyFilePath);
        var privateKey = await _fileManager.LoadFromFileAsync(_keyFilePath, cancellationToken);
        if (privateKey != null)
        {
            _rsa = RSA.Create();
            _rsa.ImportPkcs8PrivateKey(privateKey, out _);

            return _rsa;
        }

        _logger.LogDebug("No RSA private key found: generating new keys.");
        _rsa = RSA.Create(_options.RsaKeySize);

        _logger.LogDebug("Saving RSA private key to {KeyFilePath}", _keyFilePath);
        await _fileManager.SaveToFileAsync(_rsa.ExportPkcs8PrivateKey(), _keyFilePath, cancellationToken);

        return _rsa;
    }
}
