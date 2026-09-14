namespace CyberAlarm.SyslogRelay.Domain.Parsing.SonicWall;

internal sealed class SonicWallParserConfig
{
    public string[] AllowActionValues { get; init; } = [];

    public string[] DenyActionValues { get; init; } = [];

    public string[] DropActionValues { get; init; } = [];

    public string[] ReceivedBytesKeys { get; init; } = [];
}
