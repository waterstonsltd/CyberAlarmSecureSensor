namespace CyberAlarm.SyslogRelay.Domain.Pipeline.Stages;

public interface IPipelineStageLink<TOutput>
{
    IPipelineStage<TOutput>? NextStage { get; set; }
}
