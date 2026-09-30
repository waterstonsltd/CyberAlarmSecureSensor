using System.Text;
using CyberAlarm.SyslogRelay.Domain.Ingestion;
using CyberAlarm.SyslogRelay.Domain.Services;
using static CyberAlarm.SyslogRelay.Domain.Tests.Ingestion.RawExportTestData;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Ingestion;

public sealed class FileIngestionReaderTests
{
    [Theory]
    [InlineData("<134>ordinary syslog")]
    [InlineData(Example)]
    [InlineData("""{"Timestamp":"old","PatternName":"test","ParseResult":null,"RawData":null}""")]
    public async Task Nonblank_lines_are_returned_unchanged_without_seeking(string raw)
    {
        var fileManager = Substitute.For<IFileManager>();
        var stream = new NonSeekableStream(Encoding.UTF8.GetBytes("\n \n" + raw + "\nsecond line\n"));
        fileManager.OpenStreamFromFile("capture.log", CancellationToken.None).Returns(stream);
        var reader = new FileIngestionReader(fileManager);
        var records = new List<string>();
        await foreach (var line in reader.ReadAsync("capture.log", CancellationToken.None))
        {
            records.Add(line);
        }

        Assert.Equal(new[] { raw, "second line" }, records);
        fileManager.Received(1).OpenStreamFromFile("capture.log", CancellationToken.None);
        Assert.False(stream.CanRead);
    }

    [Fact]
    public async Task Early_exit_disposes_the_owned_stream()
    {
        var fileManager = Substitute.For<IFileManager>();
        var stream = new MemoryStream(Encoding.UTF8.GetBytes("first\nsecond"));
        fileManager.OpenStreamFromFile("capture.log", CancellationToken.None).Returns(stream);
        var reader = new FileIngestionReader(fileManager);
        await foreach (var line in reader.ReadAsync("capture.log", CancellationToken.None))
        {
            Assert.Equal("first", line);
            break;
        }

        Assert.False(stream.CanRead);
    }

    [Fact]
    public async Task Shared_line_reader_keeps_physical_line_numbers_and_leaves_the_stream_open()
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes("\nfirst\n \nsecond\n"));
        var lines = new List<(string, long)>();
        await foreach (var line in FileIngestionReader.ReadLinesAsync(stream, CancellationToken.None))
        {
            lines.Add(line);
        }

        Assert.Equal(new[] { ("first", 2L), ("second", 4L) }, lines);
        Assert.True(stream.CanRead);
    }

    private sealed class NonSeekableStream(byte[] bytes) : MemoryStream(bytes)
    {
        public override bool CanSeek => false;

        public override long Seek(long offset, SeekOrigin loc) => throw new NotSupportedException();
    }
}
