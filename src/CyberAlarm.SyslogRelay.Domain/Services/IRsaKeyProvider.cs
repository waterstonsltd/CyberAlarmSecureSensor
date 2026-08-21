namespace CyberAlarm.SyslogRelay.Domain.Services;

public interface IRsaKeyProvider
{
    bool KeysExist();

    Task<string> GetPublicKeyPem(CancellationToken cancellationToken);

    Task<string> GetPrivateKeyPem(CancellationToken cancellationToken);

    Task<byte[]> GetPublicKeyDer(CancellationToken cancellationToken);

    Task<byte[]> GetPrivateKeyDer(CancellationToken cancellationToken);

    byte[] GetPublicKeyDerBytes(string publicKeyPem);
}
