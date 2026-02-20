using CyberAlarm.EventBundler.Plugins.Encryptors;
using CyberAlarm.SyslogRelay.Common.EventBundler.Settings;
using System.Buffers;
using System.Security.Cryptography;

namespace CyberAlarm.EventBundler.Plugins.Encryptors;

/// <summary>
/// Provides AES-256-GCM symmetric encryption functionality.
/// </summary>
/// <remarks>
/// This implementation uses AES-256 in Galois/Counter Mode (GCM) which provides authenticated encryption.
/// The encrypted output format is: nonce (12 bytes) + tag (16 bytes) + ciphertext (variable length).
/// GCM mode provides both confidentiality and authenticity, protecting against tampering.
/// </remarks>
public sealed class Aes256GcmSymmetricEncryptor : ISymmetricEncryptor
{
    private const int KeySize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int ChunkSize = 64 * 1024; // 64KB chunks

    /// <summary>
    /// Gets the name of the encryption algorithm.
    /// </summary>
    /// <value>The algorithm name "AES-256-GCM".</value>
    public string AlgorithmName => SupportedAlgorithms.Encryptors.Aes256GcmChunked;

    /// <summary>
    /// Encrypts data from the input stream and writes the encrypted result to the output stream using symmetric encryption.
    /// </summary>
    /// <param name="input">The input stream containing the data to encrypt.</param>
    /// <param name="output">The output stream where the encrypted data will be written.</param>
    /// <param name="key">The symmetric encryption key used to encrypt the data.</param>
    /// <param name="cancellationToken">A cancellation token that can be used to cancel the encryption operation.</param>
    /// <returns>A byte array containing encryption metadata or additional information produced during the encryption process.</returns>
    public async Task EncryptStreamAsync(
        Stream input,
        Stream output,
        byte[] key,
        CancellationToken cancellationToken)
    {
        if (key.Length != KeySize)
        {
            throw new ArgumentException($"Key must be {KeySize} bytes.", nameof(key));
        }

        // Write chunk size as header (so decryptor knows how to read)
        await output.WriteAsync(BitConverter.GetBytes(ChunkSize), cancellationToken);

        using var aesGcm = new AesGcm(key, TagSize);

        byte[] inputBuffer = ArrayPool<byte>.Shared.Rent(ChunkSize);
        byte[] outputBuffer = ArrayPool<byte>.Shared.Rent(ChunkSize);
        byte[] nonce = new byte[NonceSize];
        byte[] tag = new byte[TagSize];

        try
        {
            ulong chunkCounter = 0;
            int bytesRead;

            while ((bytesRead = await input.ReadAsync(inputBuffer.AsMemory(0, ChunkSize), cancellationToken)) > 0)
            {
                // Generate unique nonce for each chunk (counter-based)
                BitConverter.TryWriteBytes(nonce.AsSpan(4), chunkCounter++);
                RandomNumberGenerator.Fill(nonce.AsSpan(0, 4)); // Add randomness

                // Encrypt this chunk
                aesGcm.Encrypt(
                    nonce,
                    inputBuffer.AsSpan(0, bytesRead),
                    outputBuffer.AsSpan(0, bytesRead),
                    tag);

                // Write: chunk_length (4 bytes) + nonce (12 bytes) + tag (16 bytes) + ciphertext
                await output.WriteAsync(BitConverter.GetBytes(bytesRead), cancellationToken);
                await output.WriteAsync(nonce, cancellationToken);
                await output.WriteAsync(tag, cancellationToken);
                await output.WriteAsync(outputBuffer.AsMemory(0, bytesRead), cancellationToken);
            }

            // Write terminator (chunk length = 0)
            await output.WriteAsync(BitConverter.GetBytes(0), cancellationToken);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(inputBuffer, clearArray: true);
            ArrayPool<byte>.Shared.Return(outputBuffer, clearArray: true);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(tag);
        }
    }

    /// <summary>
    /// Generates a cryptographically secure random 32-byte key suitable for AES-256 encryption.
    /// </summary>
    /// <returns>A 32-byte array containing a cryptographically secure random key.</returns>
    /// <remarks>
    /// The generated key should be securely stored and protected using appropriate key management practices.
    /// Never hardcode or store keys in source code or configuration files without proper encryption.
    /// </remarks>
    public byte[] GenerateKey()
    {
        var key = new byte[KeySize];
        System.Security.Cryptography.RandomNumberGenerator.Fill(key);
        return key;
    }
}
