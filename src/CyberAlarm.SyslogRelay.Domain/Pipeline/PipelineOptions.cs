namespace CyberAlarm.SyslogRelay.Domain.Pipeline;

public sealed class PipelineOptions
{
    public string AdditionalLocalSubnet { get; init; } = string.Empty;

    public int ChannelCapacity { get; init; } = 10_000;

    public int ParseFailureLogIntervalInMinutes { get; init; } = 60;

    public int PersistenceBufferSize { get; init; } = 1_000;

    public int PersistenceBufferIntervalInSeconds { get; init; } = 60;

    public bool UploadRawLogs { get; init; }

    public bool UploadOutboundData { get; init; }

    public int PatternMatchingDegreeOfParallelism { get; init; } = Environment.ProcessorCount;

    public int ParsingDegreeOfParallelism { get; init; } = Environment.ProcessorCount;

    public int ValidationDegreeOfParallelism { get; init; } = Environment.ProcessorCount;
}
