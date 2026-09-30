using System.Text.RegularExpressions;

namespace CyberAlarm.SyslogRelay.Domain.Ingestion;

internal sealed partial record MarkedFile
{
    private MarkedFile()
    {
    }

    public required string Name { get; init; }

    public int RetryCount { get; init; }

    public static MarkedFile Create(string fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName))
        {
            throw new ArgumentNullException(fileName);
        }

        var match = MarkedFilePattern().Match(fileName);

        var retryCount = match.Success
            ? int.Parse(match.Groups["retryCount"].Value)
            : 0;

        var nextCount = retryCount + 1;

        var markedFileName = match.Success
            ? $"~{nextCount}{fileName[fileName.IndexOf('.')..]}"
            : $"~{nextCount}.{fileName}";

        return new MarkedFile
        {
            Name = markedFileName,
            RetryCount = retryCount,
        };
    }

    public override string ToString() => Name;

    [GeneratedRegex(@"^~(?<retryCount>\d+)\..+$", RegexOptions.Compiled)]
    private static partial Regex MarkedFilePattern();
}
