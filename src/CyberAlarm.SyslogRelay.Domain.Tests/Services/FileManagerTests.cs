using CyberAlarm.SyslogRelay.Domain.Services;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Services;

public sealed class FileManagerTests : IDisposable
{
    private readonly string _tempDir = Path.Combine(Path.GetTempPath(), "ca-fm-tests-" + Guid.NewGuid().ToString("N"));
    private readonly FileManager _sut;

    public FileManagerTests()
    {
        Directory.CreateDirectory(_tempDir);

        var platformService = Substitute.For<IPlatformService>();
        platformService.GetPlatformType().Returns(PlatformType.Linux);

        var logger = Substitute.For<ILogger<FileManager>>();

        _sut = new FileManager(platformService, logger);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_tempDir, recursive: true);
        }
        catch (IOException)
        {
            // best-effort cleanup
        }
    }

    [Fact]
    public async Task DeserialiseFromFileAsync_returns_default_when_file_does_not_exist()
    {
        var result = await _sut.DeserialiseFromFileAsync<Dictionary<string, string>>(
            Path.Combine(_tempDir, "nonexistent.json"),
            CancellationToken.None);

        Assert.Null(result);
    }

    [Fact]
    public async Task DeserialiseFromFileAsync_returns_default_when_file_is_empty()
    {
        var filePath = Path.Combine(_tempDir, "empty.json");
        await File.WriteAllTextAsync(filePath, string.Empty);

        var result = await _sut.DeserialiseFromFileAsync<Dictionary<string, string>>(
            filePath,
            CancellationToken.None);

        Assert.Null(result);
    }

    [Fact]
    public async Task DeserialiseFromFileAsync_returns_value_when_file_has_valid_json()
    {
        var filePath = Path.Combine(_tempDir, "data.json");
        await File.WriteAllTextAsync(filePath, """{"key":"value"}""");

        var result = await _sut.DeserialiseFromFileAsync<Dictionary<string, string>>(
            filePath,
            CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal("value", result["key"]);
    }

    [Fact]
    public async Task SerialiseToFileAsync_writes_valid_json_that_can_be_read_back()
    {
        var filePath = Path.Combine(_tempDir, "output.json");
        var data = new Dictionary<string, string> { ["hello"] = "world" };

        await _sut.SerialiseToFileAsync(data, filePath, CancellationToken.None);

        var result = await _sut.DeserialiseFromFileAsync<Dictionary<string, string>>(filePath, CancellationToken.None);
        Assert.NotNull(result);
        Assert.Equal("world", result["hello"]);
    }

    [Fact]
    public async Task SerialiseToFileAsync_does_not_leave_empty_file_on_cancellation()
    {
        var filePath = Path.Combine(_tempDir, "atomic.json");
        var data = new Dictionary<string, string> { ["key"] = "value" };
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => _sut.SerialiseToFileAsync(data, filePath, cts.Token));

        // The target file must not exist (or must not be empty) — the partial temp file is cleaned up.
        Assert.False(File.Exists(filePath), "Target file should not exist after a cancelled write.");
    }

    [Fact]
    public async Task SerialiseToFileAsync_overwrites_existing_file_atomically()
    {
        var filePath = Path.Combine(_tempDir, "overwrite.json");
        await File.WriteAllTextAsync(filePath, """{"old":"data"}""");

        var newData = new Dictionary<string, string> { ["new"] = "data" };
        await _sut.SerialiseToFileAsync(newData, filePath, CancellationToken.None);

        var result = await _sut.DeserialiseFromFileAsync<Dictionary<string, string>>(filePath, CancellationToken.None);
        Assert.NotNull(result);
        Assert.Equal("data", result["new"]);
        Assert.False(result.ContainsKey("old"));
    }
}
