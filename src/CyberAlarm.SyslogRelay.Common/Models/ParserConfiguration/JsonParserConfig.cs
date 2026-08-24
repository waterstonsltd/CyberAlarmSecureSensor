namespace CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;

public sealed class JsonParserConfig : ParserConfig
{
    /// <summary>
    /// Gets the string token that immediately precedes the JSON object in the log line.
    /// The parser will locate this token, then parse the JSON that follows it.
    /// When <see langword="null"/> or empty the parser scans for the first <c>{</c> character.
    /// </summary>
    public string? JsonStartToken { get; init; }

    /// <summary>
    /// Gets a value indicating whether the protocol value from the JSON payload is
    /// an IANA protocol number (integer) rather than a protocol name string.
    /// </summary>
    public bool ProtocolIsNumber { get; init; }
}
