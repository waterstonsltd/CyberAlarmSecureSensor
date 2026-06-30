using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;

namespace CyberAlarm.SyslogRelay.Common.EventBundler.Models;

/// <summary>
/// Fixed-size header for CyberAlarm bundle files.
/// Format: [Magic][Version][Reserved×3][JSON Length][Payload Length][Signature Length]
/// Total size: 22 bytes.
/// </summary>
public struct BundleHeader
{
    /// <summary>
    /// Magic number identifying CyberAlarm bundle files ("CALR" in ASCII).
    /// Used for quick validation of file type.
    /// </summary>
    public const uint Magic = 0x43414C52; // "CALR"

    /// <summary>
    /// Current bundle format version (v1).
    /// Allows for future format evolution and backward compatibility.
    /// </summary>
    public const byte Version = 0x01;

    /// <summary>
    /// Total size of the serialized header in bytes.
    /// </summary>
    public const int HeaderSize = 22;

    /// <summary>
    /// Gets or sets the Magic number for file type validation. Should always equal Magic constant.
    /// Offset: 0, Size: 4 bytes.
    /// </summary>
    public uint MagicNumber { get; set; }

    /// <summary>
    /// Gets or sets the Bundle format version number.
    /// Offset: 4, Size: 1 byte.
    /// </summary>
    public byte VersionNumber { get; set; }

    /// <summary>
    /// Gets or sets the Reserved byte for future use (e.g., compression flags, encryption options).
    /// Offset: 5, Size: 1 byte.
    /// </summary>
    public byte Reserved1 { get; set; }

    /// <summary>
    /// Gets or sets the Reserved byte for future use.
    /// Offset: 6, Size: 1 byte.
    /// </summary>
    public byte Reserved2 { get; set; }

    /// <summary>
    /// Gets or sets the Reserved byte for future use.
    /// Offset: 7, Size: 1 byte.
    /// </summary>
    public byte Reserved3 { get; set; }

    /// <summary>
    /// Gets or sets the Length of the JSON metadata section in bytes.
    /// Offset: 8, Size: 4 bytes (max ~4GB, typically < 1KB).
    /// </summary>
    public uint JsonLength { get; set; }

    /// <summary>
    /// Gets or sets the Length of the encrypted payload section in bytes.
    /// Offset: 12, Size: 8 bytes (max ~16 exabytes).
    /// </summary>
    public ulong PayloadLength { get; set; }

    /// <summary>
    /// Gets or sets the Length of the RSA signature in bytes.
    /// Offset: 20, Size: 2 bytes (RSA-4096 = 512 bytes).
    /// </summary>
    public ushort SignatureLength { get; set; }

    /// <summary>
    /// Serializes the header to a stream in big-endian (network byte order) format.
    /// </summary>
    /// <param name="stream">Target stream to write the header to.</param>
    public void WriteTo(Stream stream)
    {
        var buffer = new byte[HeaderSize];

        // Offset 0-3: Magic number (4 bytes, big-endian)
        BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(0), MagicNumber);

        // Offset 4-7: Version and reserved bytes (4 bytes, single bytes)
        buffer[4] = VersionNumber;
        buffer[5] = Reserved1;
        buffer[6] = Reserved2;
        buffer[7] = Reserved3;

        // Offset 8-11: JSON length (4 bytes, big-endian)
        BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(8), JsonLength);

        // Offset 12-19: Payload length (8 bytes, big-endian)
        BinaryPrimitives.WriteUInt64BigEndian(buffer.AsSpan(12), PayloadLength);

        // Offset 20-21: Signature length (2 bytes, big-endian)
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(20), SignatureLength);

        stream.Write(buffer);
    }

    /// <summary>
    /// Deserializes a header from a stream and validates magic number and version.
    /// </summary>
    /// <param name="stream">Source stream to read the header from.</param>
    /// <returns>Parsed and validated header.</returns>
    /// <exception cref="InvalidDataException">Thrown if magic number is invalid or version is unsupported.</exception>
    public static BundleHeader ReadFrom(Stream stream)
    {
        // Read exactly 22 bytes for the header
        var buffer = new byte[HeaderSize];
        stream.ReadExactly(buffer);

        // Parse header fields from big-endian format
        var header = new BundleHeader
        {
            MagicNumber = BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(0)),      // Offset 0-3
            VersionNumber = buffer[4],                                                  // Offset 4
            Reserved1 = buffer[5],                                                      // Offset 5
            Reserved2 = buffer[6],                                                      // Offset 6
            Reserved3 = buffer[7],                                                      // Offset 7
            JsonLength = BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(8)),       // Offset 8-11
            PayloadLength = BinaryPrimitives.ReadUInt64BigEndian(buffer.AsSpan(12)),   // Offset 12-19
            SignatureLength = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(20)), // Offset 20-21
        };

        // Validate this is actually a CyberAlarm bundle file
        if (header.MagicNumber != Magic)
        {
            throw new InvalidDataException("Invalid bundle magic number");
        }

        // Ensure we can handle this version
        if (header.VersionNumber != Version)
        {
            throw new InvalidDataException($"Unsupported version: {header.VersionNumber}");
        }

        return header;
    }
}
