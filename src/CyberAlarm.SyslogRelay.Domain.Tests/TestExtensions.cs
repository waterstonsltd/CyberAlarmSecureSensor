using System.Text;
using System.Text.Json;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Tests;

internal static class TestExtensions
{
    extension<T>(T value)
    {
        public StringContent ToJsonStringContent()
        {
            var json = JsonSerializer.Serialize(value);
            return new StringContent(json, Encoding.UTF8, "application/json");
        }
    }

    extension(Result)
    {
        public static Result Fail() => Result.Fail(Guid.NewGuid().ToString());
    }
}
