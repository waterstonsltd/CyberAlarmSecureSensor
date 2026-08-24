using System.Text.RegularExpressions;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;
using CyberAlarm.SyslogRelay.Domain.Parsing.Errors;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Parsing.LinuxNetfilter;

// Parses Linux netfilter kernel logs where action is encoded in a chain token
// and traffic fields are emitted as key/value pairs (SRC, DST, PROTO, SPT, DPT).
internal sealed class LinuxNetfilterParser : KeyValueParserBase<LinuxNetfilterParserConfig>
{
    [ThreadStatic]
    private static Dictionary<string, string>? _keyValueBuffer;

    private Regex? _actionRegex;

    protected override Result ProcessConfig(LinuxNetfilterParserConfig config)
    {
        if (config.ActionCaptureGroup < 1)
        {
            return Result.Fail("ActionCaptureGroup must be greater than 0.");
        }

        _actionRegex = new Regex(
            config.ActionExtractRegex,
            RegexOptions.Compiled | RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(1));

        return Result.Ok();
    }

    protected override Result<ParseResult> ParseLog(string log, LinuxNetfilterParserConfig config)
    {
        ArgumentNullException.ThrowIfNull(_actionRegex);

        var actionMatch = _actionRegex.Match(log);
        if (!actionMatch.Success || actionMatch.Groups.Count <= config.ActionCaptureGroup)
        {
            return new FormatError();
        }

        var keyValues = log.ParseKeyValues(GetBuffer());
        if (keyValues is null ||
            !keyValues.TryGetValueFrom(config.SourceIpKeys, out var sourceIp) ||
            (!keyValues.TryGetValueFrom(config.DestinationIpKeys, out var destinationIp) && !config.IsDestinationIpOptional) ||
            (!keyValues.TryGetValueFrom(config.SourcePortKeys, out var sourcePortValue) && !config.IsSourcePortOptional) ||
            (!keyValues.TryGetValueFrom(config.DestinationPortKeys, out var destinationPortValue) && !config.IsDestinationPortOptional) ||
            (!keyValues.TryGetValueFrom(config.ProtocolKeys, out var protocolValue) && !config.IsProtocolOptional))
        {
            return new UnparsableEventError();
        }

        return ToParseResult(
            config,
            sourceIp,
            destinationIp,
            sourcePortValue,
            destinationPortValue,
            protocolValue,
            actionMatch.Groups[config.ActionCaptureGroup].Value,
            keyValues.ExtractDuration(config.DurationKeys, config.DurationIsSeconds),
            keyValues.ExtractBytes(config.TotalBytesKeys, config.SentBytesKeys, config.ReceivedBytesKeys));
    }

    private static Dictionary<string, string> GetBuffer()
    {
        _keyValueBuffer ??= new Dictionary<string, string>(32);
        _keyValueBuffer.Clear();
        return _keyValueBuffer;
    }
}
