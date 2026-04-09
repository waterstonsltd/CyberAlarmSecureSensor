using System.Net;
using CyberAlarm.SyslogRelay.Common.Models;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Pipeline.Stages;

internal sealed class ValidationStage(
    PipelineStageServices services,
    ILogger<ValidationStage> logger)
    : PipelineStageBase<ParsingStageOutput, ValidationStageOutput>(services, logger)
{
    private readonly PipelineOptions _options = services.Options;
    private readonly ILogger<ValidationStage> _logger = logger;
    private readonly PipelineMetrics _metrics = services.Metrics;
    private readonly int _degreeOfParallelism = services.Options.ValidationDegreeOfParallelism;

    private readonly HashSet<IPNetwork> _localSubnets = [
        IPNetwork.Parse("10.0.0.0/8"),
        IPNetwork.Parse("172.16.0.0/12"),
        IPNetwork.Parse("192.168.0.0/16"),
        IPNetwork.Parse("fc00::/7"),
        IPNetwork.Parse("fd00::/8"),
    ];

    protected override int DegreeOfParallelism => _degreeOfParallelism;

    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        await base.StartAsync(cancellationToken);

        if (IPNetwork.TryParse(_options.AdditionalLocalSubnet, out var additionalLocalSubnet))
        {
            _localSubnets.Add(additionalLocalSubnet);
            _logger.LogDebug("Added additional local subnet '{AdditionalLocalSubnet}' to validation stage.", additionalLocalSubnet);
        }
        else if (!string.IsNullOrEmpty(_options.AdditionalLocalSubnet))
        {
            _logger.LogWarning("Additional local subnet '{AdditionalLocalSubnet}' cannot be parsed. Ensure it's in CIDR format, for example: 10.0.0.0/8", _options.AdditionalLocalSubnet);
        }
    }

    protected override Task<ValidationStageOutput> ProcessMessageAsync(ParsingStageOutput input, CancellationToken cancellationToken)
    {
        if (input.PatternMatchResult is null)
        {
            return Output(ValidationStatus.UnableToPatternMatch);
        }

        if (input.IsIgnored)
        {
            return Output(ValidationStatus.Ignored);
        }

        if (input.ParseResult is null)
        {
            return Output(ValidationStatus.UnableToParse);
        }

        if (IsLocalEvent(input.ParseResult))
        {
            return Output(ValidationStatus.LocalOnlyEvent);
        }

        return Output(ValidationStatus.Success);

        Task<ValidationStageOutput> Output(ValidationStatus validationStatus)
        {
            _metrics.ValidationOutcomes.Add(1, new KeyValuePair<string, object?>("outcome", validationStatus.ToString()));
            return Task.FromResult(new ValidationStageOutput(
                input.SyslogEvent,
                input.PatternMatchResult,
                input.ParseResult,
                new(validationStatus)));
        }
    }

    private bool IsLocalEvent(ParseResult parseResult) =>
        IsLocalIp(parseResult.SourceIp) &&
        IsLocalIp(parseResult.DestinationIp);

    private bool IsLocalIp(string? ip)
    {
        if (string.IsNullOrWhiteSpace(ip) || !IPAddress.TryParse(ip, out var address))
        {
            return false;
        }

        return _localSubnets.Any(subnet => subnet.Contains(address));
    }
}
