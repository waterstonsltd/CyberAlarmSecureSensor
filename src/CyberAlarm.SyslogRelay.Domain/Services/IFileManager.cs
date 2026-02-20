namespace CyberAlarm.SyslogRelay.Domain.Services;

public interface IFileManager
{
    bool CanWriteFile(string filePath);

    bool Exists(string path);

    string GetDataPath();

    string GetLogsFolder();

    string GetProcessingFolder();

    string GetSourceGroupFolder();

    string GetUploadFolder();

    string GetFailedFolder();

    string GetTemporaryFolder();

    void Move(string sourceFilePath, string destinationFilePath);

    void Delete(string filePath);

    IEnumerable<string> ListDirectoryNamesInDirectory(string directoryPath);

    IEnumerable<string> ListFileNamesInDirectory(string directoryPath);

    IEnumerable<string> ListFilesInDirectory(string directoryPath);

    Task<T?> DeserialiseFromFileAsync<T>(string filePath, CancellationToken cancellationToken);

    Task SerialiseToFileAsync<T>(T value, string filePath, CancellationToken cancellationToken);

    Task AppendAndSaveItemsAsNdjson<T>(IEnumerable<T> items, string filePath, CancellationToken cancellationToken);

    Task<IEnumerable<T>> DeserialiseFromNdjson<T>(string filePath, CancellationToken cancellationToken);

    Task<byte[]?> LoadFromFileAsync(string filePath, CancellationToken cancellationToken);

    Stream OpenStreamFromFile(string filePath, CancellationToken cancellationToken);

    Stream OpenWriteStreamForFile(string filePath, CancellationToken cancellationToken);

    Task SaveToFileAsync(byte[] value, string filePath, CancellationToken cancellationToken);

    long GetFileSize(string file);
}
