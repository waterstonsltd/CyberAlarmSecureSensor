namespace CyberAlarm.SyslogRelay.Domain.Upload.Services;

/// <summary>
/// Aggregates the upload pipeline step services to reduce constructor parameter counts.
/// </summary>
public sealed class UploadPipelineServices(
    IFileSelector fileSelector,
    ISourceGrouper sourceGrouper,
    IFileBundler fileBundler,
    ISecureUploader secureUploader)
{
    public IFileSelector FileSelector { get; } = fileSelector;

    public ISourceGrouper SourceGrouper { get; } = sourceGrouper;

    public IFileBundler FileBundler { get; } = fileBundler;

    public ISecureUploader SecureUploader { get; } = secureUploader;
}
