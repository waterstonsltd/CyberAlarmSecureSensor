using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Registration;

public sealed record RegistrationToken(string Value)
{
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
