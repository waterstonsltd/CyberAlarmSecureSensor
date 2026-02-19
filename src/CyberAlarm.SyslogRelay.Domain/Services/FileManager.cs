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

    /// <summary>
    /// Files in here are currently being processed. On startup everything in this folder can be deleted.
    /// </summary>
    private const string WorkingFolder = "temporaryFiles";

    private static readonly JsonSerializerOptions _options = new();

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
        return await JsonSerializer.DeserializeAsync<T>(openStream, _options, cancellationToken);
    }

    public async Task SerialiseToFileAsync<T>(T value, string filePath, CancellationToken cancellationToken)
    {
        EnsureFolderExists(filePath);

        _logger.LogDebug("Serialising to file '{FilePath}'.", filePath);
        await using var stream = File.Create(filePath);
        await JsonSerializer.SerializeAsync(stream, value, _options, cancellationToken);
    }

    public async Task AppendAndSaveItemsAsNdjson<T>(IEnumerable<T> items, string filePath, CancellationToken cancellationToken)
    {
        EnsureFolderExists(filePath);
        _logger.LogDebug("Appending items as NDJSON to file '{FilePath}'.", filePath);

        var itemsList = items.ToList();
        if (itemsList.Count == 0)
        {
            _logger.LogDebug("No items to append.");
            return;
        }

        await using var stream = new FileStream(filePath, FileMode.Append, FileAccess.Write, FileShare.None, bufferSize: 65536, useAsync: true);
        await using var writer = new StreamWriter(stream);

        foreach (var item in itemsList)
        {
            var json = JsonSerializer.Serialize(item, _options);
            await writer.WriteLineAsync(json.AsMemory(), cancellationToken);
        }

        await writer.FlushAsync(cancellationToken);

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

        using var stream = File.OpenRead(filePath);
        using var reader = new StreamReader(stream);

        while (!cancellationToken.IsCancellationRequested)
        {
            var line = await reader.ReadLineAsync(cancellationToken);
            if (line == null)
            {
                return items;
            }

            if (string.IsNullOrWhiteSpace(line.Trim()))
            {
                continue;
            }

            items.Add(JsonSerializer.Deserialize<T>(line, _options)!);
        }

        return items;
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
            _logger.LogWarning("Source directory '{DirectoryPath}' does not exist.", directoryPath);
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
