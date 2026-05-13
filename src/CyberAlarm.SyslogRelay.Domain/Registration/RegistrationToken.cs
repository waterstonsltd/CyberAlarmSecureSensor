using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Registration;

public sealed record RegistrationToken(string Value)
{
    /// <summary>
    /// Extracts the bucket segment (first dot-delimited part) from a raw token string.
    /// Returns an empty string if the token is null, empty, or malformed.
    /// </summary>
    public static string GetBucket(string? token) =>
        string.IsNullOrEmpty(token) ? string.Empty : token.Split('.')[0];

    public static Result Validate(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return Result.Fail("Registration token is missing.");
        }

        if (!IsValid(value))
        {
            return Result.Fail("Registration token is invalid.");
        }

        return Result.Ok();
    }

    private static bool IsValid(string value) =>
        value.Count(x => x == '.') == 2 && char.IsDigit(value[0]);
}
