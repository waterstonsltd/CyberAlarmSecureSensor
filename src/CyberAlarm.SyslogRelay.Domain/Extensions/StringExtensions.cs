namespace CyberAlarm.SyslogRelay.Domain.Extensions;

internal static class StringExtensions
{
    public static string SelectElement(this string value, int elementNumber, char separator)
    {
        var elements = value.Split(separator);
        return elementNumber < elements.Length ? elements[elementNumber] : string.Empty;
    }
}
