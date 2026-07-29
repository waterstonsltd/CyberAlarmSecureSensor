using System.IO.Compression;
using CyberAlarm.SyslogRelay.Domain.Diagnostics;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Diagnostics;

public sealed class SupportBundleServiceTests : IDisposable
{
    private readonly DiagnosticsServiceBuilder _diagnosticsBuilder = new();

    public void Dispose() => _diagnosticsBuilder.Dispose();

    private SupportBundleService BuildSut() =>
        new(
            _diagnosticsBuilder.FileManager,
            _diagnosticsBuilder.PlatformService,
            _diagnosticsBuilder.Build(),
            Options.Create(_diagnosticsBuilder.RelayOptions));

    [Fact]
    public async Task CreateBundleAsync_returns_path_ending_with_dot_zip()
    {
        // Arrange
        var sut = BuildSut();

        // Act
        var zipPath = await sut.CreateBundleAsync(CancellationToken.None);

        // Assert
        try
        {
            Assert.EndsWith(".zip", zipPath);
        }
        finally
        {
            TryDelete(zipPath);
        }
    }

    [Fact]
    public async Task CreateBundleAsync_creates_zip_file_at_returned_path()
    {
        // Arrange
        var sut = BuildSut();

        // Act
        var zipPath = await sut.CreateBundleAsync(CancellationToken.None);

        // Assert
        try
        {
            Assert.True(File.Exists(zipPath));
        }
        finally
        {
            TryDelete(zipPath);
        }
    }

    [Fact]
    public async Task CreateBundleAsync_zip_contains_diagnostics_txt_entry()
    {
        // Arrange
        var sut = BuildSut();

        // Act
        var zipPath = await sut.CreateBundleAsync(CancellationToken.None);

        // Assert
        try
        {
            using var zip = ZipFile.OpenRead(zipPath);
            Assert.Contains(zip.Entries, e => e.FullName == "diagnostics.txt");
        }
        finally
        {
            TryDelete(zipPath);
        }
    }

    [Fact]
    public async Task CreateBundleAsync_zip_contains_file_counts_txt_entry()
    {
        // Arrange
        var sut = BuildSut();

        // Act
        var zipPath = await sut.CreateBundleAsync(CancellationToken.None);

        // Assert
        try
        {
            using var zip = ZipFile.OpenRead(zipPath);
            Assert.Contains(zip.Entries, e => e.FullName == "file-counts.txt");
        }
        finally
        {
            TryDelete(zipPath);
        }
    }

    [Fact]
    public async Task CreateBundleAsync_zip_contains_key_exists_txt_entry()
    {
        // Arrange
        var sut = BuildSut();

        // Act
        var zipPath = await sut.CreateBundleAsync(CancellationToken.None);

        // Assert
        try
        {
            using var zip = ZipFile.OpenRead(zipPath);
            Assert.Contains(zip.Entries, e => e.FullName == "key-exists.txt");
        }
        finally
        {
            TryDelete(zipPath);
        }
    }

    [Fact]
    public async Task CreateBundleAsync_zip_does_not_contain_raw_private_key()
    {
        // Arrange — write a fake key.der so the service can detect it exists
        var keyPath = Path.Combine(_diagnosticsBuilder.TempDir, "key.der");
        await File.WriteAllBytesAsync(keyPath, [0x01, 0x02, 0x03]);

        var sut = BuildSut();

        // Act
        var zipPath = await sut.CreateBundleAsync(CancellationToken.None);

        // Assert — the zip must not contain any entry with the actual key bytes
        try
        {
            using var zip = ZipFile.OpenRead(zipPath);
            Assert.DoesNotContain(zip.Entries, e => e.FullName == "key.der");
        }
        finally
        {
            TryDelete(zipPath);
        }
    }

    [Fact]
    public async Task CreateBundleAsync_zip_contains_state_redacted_json_with_token_redacted()
    {
        // Arrange — write a real state.json so File.Exists passes
        var stateJson = """{"IsRegistered":true,"IsUploadBlocked":false,"StatusETag":"etag","RegistrationToken":"1.secret.abc"}""";
        await File.WriteAllTextAsync(Path.Combine(_diagnosticsBuilder.TempDir, "state.json"), stateJson);

        _diagnosticsBuilder.WithState(new RelayStateBuilder()
            .WithRegistrationToken("1.secret.abc")
            .Build());

        var sut = BuildSut();

        // Act
        var zipPath = await sut.CreateBundleAsync(CancellationToken.None);

        // Assert
        try
        {
            using var zip = ZipFile.OpenRead(zipPath);
            var entry = Assert.Single(zip.Entries, e => e.FullName == "state-redacted.json");

            await using var stream = entry.Open();
            using var reader = new StreamReader(stream);
            var content = await reader.ReadToEndAsync();

            Assert.Contains("[REDACTED]", content);
            Assert.DoesNotContain("1.secret.abc", content);
        }
        finally
        {
            TryDelete(zipPath);
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
            // best-effort cleanup
        }
    }
}
