using System.Diagnostics.Metrics;

namespace CyberAlarm.SyslogRelay.Domain.Upload.Services;

internal sealed class UploadMetrics
{
    public const string MeterName = "CyberAlarm.SyslogRelay.Upload";

    public UploadMetrics(IMeterFactory meterFactory)
    {
        var meter = meterFactory.Create(MeterName);

        FilesUploaded = meter.CreateCounter<long>(
            "upload.files_uploaded",
            description: "Number of files successfully uploaded to the platform.");

        FilesFailed = meter.CreateCounter<long>(
            "upload.files_failed",
            description: "Number of files that failed to upload during the upload cycle.");

        CycleDuration = meter.CreateHistogram<double>(
            "upload.cycle_duration",
            unit: "ms",
            description: "Total time taken to complete an upload cycle, from file selection to final file uploaded.");
    }

    public Counter<long> FilesUploaded { get; }

    public Counter<long> FilesFailed { get; }

    public Histogram<double> CycleDuration { get; }
}
