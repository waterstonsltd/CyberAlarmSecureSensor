namespace CyberAlarm.SyslogRelay.Domain.Upload.Services;

/// <summary>
/// Result of an upload cycle, indicating how many files were processed.
/// </summary>
/// <param name="FilesUploaded">Number of files successfully uploaded.</param>
/// <param name="FilesFailed">Number of files that failed to upload.</param>
public readonly record struct UploadResult(int FilesUploaded, int FilesFailed)
{
    /// <summary>
    /// Returns true if at least one file was successfully uploaded.
    /// </summary>
    public bool HasUploads => FilesUploaded > 0;

    /// <summary>
    /// An empty result indicating no files were processed.
    /// </summary>
    public static UploadResult Empty => new(0, 0);
}
