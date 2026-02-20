namespace CyberAlarm.SyslogRelay.Common.EventBundler.Settings;

public static class SupportedAlgorithms
{
    public static class Compressors
    {
        public const string Brotli = "Brotli";
    }

    public static class Signers
    {
        public const string RsaPssSha256 = "RSA-PSS-SHA256";
    }

    public static class Encryptors
    {
        public const string RsaOaepSha256 = "RSA-OAEP-SHA256";
        public const string Aes256GcmChunked = "AES-256-GCM-CHUNKED";
    }
}
