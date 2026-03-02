using System.Net;
using System.Text;

namespace CyberAlarm.SyslogRelay.Common.Models;

public sealed record SyslogEvent(
    DateTime Timestamp,
    EventSource EventSource,
    string RawData)
{
    public static SyslogEvent FromFile(string source, string rawData) =>
        Create(IngestionMethod.File, source, rawData);

    public static SyslogEvent FromTcp(string source, string rawData) =>
        Create(IngestionMethod.Tcp, source, rawData);

    public static SyslogEvent FromUdp(IPEndPoint source, ReadOnlySpan<byte> rawData) =>
        Create(IngestionMethod.Udp, source.Address.ToString(), Encoding.UTF8.GetString(rawData));

    public static SyslogEvent Create(IngestionMethod ingestionMethod, string source, string rawData) =>
        new(DateTime.UtcNow, new(ingestionMethod, source), rawData);
}
