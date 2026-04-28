using System.Buffers;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using static System.Environment;

namespace CyberAlarm.SyslogRelay.Domain.Services;

internal sealed class FileManager(IPlatformService platformService, ILogger<FileManager> logger) : IFileManager
{
    private const string DataFolder = "syslog-relay";
    private const string TemporaryFolder = ".tmp";
    private const string LogsFolder = "logs";
    private const string ProcessingFolder = "processing";
    private const string SourceGroupFolder = "source-groups";
    private const string UploadFolder = "upload";
    private const string FailedFolder = "failed";
    private const string EventsMetaDataFile = "metadata.json";

    /// <summary>
    /// Files in here are currently being processed. On startup everything in this folder can be deleted.
    /// </summary>
    private const string WorkingFolder = "temporaryFiles";

    private const byte LineFeed = 0x0A;

    private readonly IPlatformService _platformService = platformService;
    private readonly ILogger<FileManager> _logger = logger;

    private string? _dataPath;

    public bool CanWriteFile(string filePath)
    {
        try
        {
            _logger.LogDebug("Creating file '{FilePath}' to check write access.", filePath);
            using (File.Create(filePath))
            {
                // Utilising using statement as discards with
                // using declarations are not supported (yet)
            }

            _logger.LogDebug("Deleting file '{FilePath}'.", filePath);
            File.Delete(filePath);

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred when checking '{FilePath}' for write access.", filePath);
            return false;
        }
    }

    public bool Exists(string path) =>
        File.Exists(path) || Directory.Exists(path);

    public string GetDataPath()
    {
        if (string.IsNullOrEmpty(_dataPath))
        {
            _dataPath = _platformService.GetPlatformType() switch
            {
                PlatformType.Linux => $"/var/lib/{DataFolder}",
                PlatformType.Windows => Path.Combine(GetFolderPath(SpecialFolder.CommonApplicationData), DataFolder),
                _ => string.Empty,
            };
        }

        return _dataPath;
    }

    public string GetEventsMetaDataFilePath() => Path.Combine(GetDataPath(), TemporaryFolder, EventsMetaDataFile);

    public string GetLogsFolder() => Path.Combine(GetDataPath(), TemporaryFolder, LogsFolder);

    public string GetProcessingFolder() => Path.Combine(GetDataPath(), TemporaryFolder, ProcessingFolder);

    public string GetSourceGroupFolder() => Path.Combine(GetDataPath(), TemporaryFolder, SourceGroupFolder);

    public string GetUploadFolder() => Path.Combine(GetDataPath(), TemporaryFolder, UploadFolder);

    public string GetFailedFolder() => Path.Combine(GetDataPath(), TemporaryFolder, FailedFolder);

    public string GetTemporaryFolder() => Path.Combine(GetDataPath(), TemporaryFolder, WorkingFolder);

    public async Task<T?> DeserialiseFromFileAsync<T>(string filePath, CancellationToken cancellationToken)
    {
        if (!File.Exists(filePath))
        {
            _logger.LogDebug("Cannot deserialise from file: '{FilePath}' not found.", filePath);
            return default;
        }

        _logger.LogDebug("Deserialising from file '{FilePath}'.", filePath);
        using var openStream = File.OpenRead(filePath);
        return await JsonSerializer.DeserializeAsync<T>(openStream, SerializationOptions.Default, cancellationToken);
    }

    public async Task SerialiseToFileAsync<T>(T value, string filePath, CancellationToken cancellationToken)
    {
        EnsureFolderExists(filePath);

        _logger.LogDebug("Serialising to file '{FilePath}'.", filePath);
        await using var stream = File.Create(filePath);
        await JsonSerializer.SerializeAsync(stream, value, SerializationOptions.Default, cancellationToken);
    }

    public async Task AppendAndSaveItemsAsNdjson<T>(
       IEnumerable<T> items,
       string filePath,
       CancellationToken cancellationToken)
    {
        EnsureFolderExists(filePath);

        var itemsList = items as IReadOnlyCollection<T> ?? items.ToList();
        if (itemsList.Count == 0)
        {
            _logger.LogDebug("No items to append to '{FilePath}'.", filePath);
            return;
        }

        _logger.LogDebug("Appending {Count} items as NDJSON to file '{FilePath}'.", itemsList.Count, filePath);

        const int flushThreshold = 65_536;

        await using var stream = new FileStream(
            filePath,
            FileMode.Append,
            FileAccess.Write,
            FileShare.None,
            bufferSize: 65_536,
            useAsync: true);

        var buffer = new ArrayBufferWriter<byte>(initialCapacity: flushThreshold);
        using var jsonWriter = new Utf8JsonWriter(buffer);

        foreach (var item in itemsList)
        {
            JsonSerializer.Serialize(jsonWriter, item, SerializationOptions.Ndjson);

            // Append newline directly into the buffer to complete the NDJSON record.
            buffer.GetSpan(1)[0] = LineFeed;
            buffer.Advance(1);

            // Reset the writer state so the next item can start a new root JSON value.
            // This does not clear the buffer — written bytes are preserved.
            jsonWriter.Reset(buffer);

            // Flush in ~64KB batches to reduce async overhead and syscalls.
            if (buffer.WrittenCount >= flushThreshold)
            {
                await stream.WriteAsync(buffer.WrittenMemory, cancellationToken);
                buffer.Clear();
                jsonWriter.Reset(buffer);
            }
        }

        if (buffer.WrittenCount > 0)
        {
            await stream.WriteAsync(buffer.WrittenMemory, cancellationToken);
        }

        _logger.LogDebug("Successfully appended {Count} items to '{FilePath}'.", itemsList.Count, filePath);
    }

    public async Task<IEnumerable<T>> DeserialiseFromNdjson<T>(string filePath, CancellationToken cancellationToken)
    {
        var items = new List<T>();

        if (!File.Exists(filePath))
        {
            _logger.LogDebug("Cannot deserialise from file: '{FilePath}' not found.", filePath);
            return items;
        }

        _logger.LogDebug("Deserialising as NDJSON from file '{FilePath}'.", filePath);

        await using var stream = File.OpenRead(filePath);
        using var reader = new StreamReader(stream);

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var line = await reader.ReadLineAsync(cancellationToken);
            if (line is null)
            {
                return items;
            }

            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            var item = JsonSerializer.Deserialize<T>(line, SerializationOptions.Ndjson);
            if (item is not null)
            {
                items.Add(item);
            }
        }
    }

    public async Task<byte[]?> LoadFromFileAsync(string filePath, CancellationToken cancellationToken)
    {
        if (!File.Exists(filePath))
        {
            _logger.LogDebug("Cannot load from file: '{FilePath}' not found.", filePath);
            return default;
        }

        _logger.LogDebug("Loading from file '{FilePath}'.", filePath);
        return await File.ReadAllBytesAsync(filePath, cancellationToken);
    }

    public Stream OpenStreamFromFile(string filePath, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        _logger.LogDebug("Opening file stream from file '{FilePath}'.", filePath);
        return File.OpenRead(filePath);
    }

    public Stream OpenWriteStreamForFile(string filePath, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        EnsureFolderExists(filePath);

        _logger.LogDebug("Opening file stream from file '{FilePath}' for writing.", filePath);
        return new FileStream(filePath, FileMode.Create, FileAccess.ReadWrite);
    }

    public async Task SaveToFileAsync(byte[] value, string filePath, CancellationToken cancellationToken)
    {
        EnsureFolderExists(filePath);

        _logger.LogDebug("Saving to file '{FilePath}'.", filePath);
        await File.WriteAllBytesAsync(filePath, value, cancellationToken);
    }

    public IEnumerable<string> ListDirectoryNamesInDirectory(string directoryPath)
    {
        if (!Directory.Exists(directoryPath))
        {
            _logger.LogWarning("Directory '{DirectoryPath}' does not exist.", directoryPath);
            return [];
        }

        return Directory
            .GetDirectories(directoryPath)
            .Select(path => Path.GetFileName(path));
    }

    public IEnumerable<string> ListFileNamesInDirectory(string directoryPath)
    {
        if (!Directory.Exists(directoryPath))
        {
            _logger.LogWarning("Directory '{DirectoryPath}' does not exist.", directoryPath);
            return [];
        }

        return Directory
            .EnumerateFiles(directoryPath)
            .Select(path => Path.GetFileName(path));
    }

    public IEnumerable<string> ListFilesInDirectory(string directoryPath)
    {
        if (!Directory.Exists(directoryPath))
        {
            _logger.LogDebug("Source directory '{DirectoryPath}' does not exist.", directoryPath);
            return [];
        }

        return Directory.EnumerateFiles(directoryPath, "*", new EnumerationOptions { RecurseSubdirectories = true });
    }

    public void Move(string sourceFilePath, string destinationFilePath)
    {
        EnsureFolderExists(destinationFilePath);

        File.Move(sourceFilePath, destinationFilePath);
    }

    public void Delete(string filePath)
    {
        File.Delete(filePath);
    }

    public void CreateEmptyFile(string filePath)
    {
        EnsureFolderExists(filePath);
        using var file = File.Create(filePath);
    }

    public long GetFileSize(string file)
    {
        var inputFileInfo = new FileInfo(file);
        return inputFileInfo.Length;
    }

    private static void EnsureFolderExists(string destinationFilePath)
    {
        var targetFolder = Path.GetDirectoryName(destinationFilePath);
        if (!string.IsNullOrWhiteSpace(targetFolder) && !Directory.Exists(targetFolder))
        {
            Directory.CreateDirectory(targetFolder!);
        }
    }
}
