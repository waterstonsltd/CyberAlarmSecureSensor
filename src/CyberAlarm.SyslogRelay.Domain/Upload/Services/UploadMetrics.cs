using System.Diagnostics.Metrics;

namespace CyberAlarm.SyslogRelay.Domain.Upload.Services;

internal sealed class UploadMetrics
{
    public const string MeterName = "CyberAlarm.SyslogRelay.Upload";

    public UploadMetrics(IMeterFactory meterFactory)
    {
        var meter = meterFactory.Create(MeterName);

        // File selection
        SelectorFilesSelected = meter.CreateCounter<long>(
            "upload.selector.files_selected",
            description: "Number of files moved from the logs folder into the processing folder during file selection.");

        SelectorDuration = meter.CreateHistogram<double>(
            "upload.selector.duration",
            unit: "ms",
            description: "Time taken to complete a file selection pass.");

        // Source grouping
        GroupingFilesProcessed = meter.CreateCounter<long>(
            "upload.grouping.files_processed",
            description: "Number of input files successfully processed during source grouping.");

        GroupingFilesFailed = meter.CreateCounter<long>(
            "upload.grouping.files_failed",
            description: "Number of input files that failed during source grouping.");

        GroupingEventsWritten = meter.CreateCounter<long>(
            "upload.grouping.events_written",
            description: "Total number of events written to grouped output files.");

        GroupingOutputFilesCreated = meter.CreateCounter<long>(
            "upload.grouping.output_files_created",
            description: "Number of grouped output files created during source grouping.");

        GroupingDuration = meter.CreateHistogram<double>(
            "upload.grouping.duration",
            unit: "ms",
            description: "Time taken to complete a source grouping pass.");

        // Bundling
        BundlingFilesBundled = meter.CreateCounter<long>(
            "upload.bundling.files_bundled",
            description: "Number of files successfully encrypted, compressed, and bundled for upload.");

        BundlingFilesFailed = meter.CreateCounter<long>(
            "upload.bundling.files_failed",
            description: "Number of files that failed during the bundling step.");

        BundlingDuration = meter.CreateHistogram<double>(
            "upload.bundling.duration",
            unit: "ms",
            description: "Time taken to complete a bundling pass.");

        // Upload
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

    // Selector
    public Counter<long> SelectorFilesSelected { get; }

    public Histogram<double> SelectorDuration { get; }

    // Grouping
    public Counter<long> GroupingFilesProcessed { get; }

    public Counter<long> GroupingFilesFailed { get; }

    public Counter<long> GroupingEventsWritten { get; }

    public Counter<long> GroupingOutputFilesCreated { get; }

    public Histogram<double> GroupingDuration { get; }

    // Bundling
    public Counter<long> BundlingFilesBundled { get; }

    public Counter<long> BundlingFilesFailed { get; }

    public Histogram<double> BundlingDuration { get; }

    // Upload
    public Counter<long> FilesUploaded { get; }

    public Counter<long> FilesFailed { get; }

    public Histogram<double> CycleDuration { get; }
}
