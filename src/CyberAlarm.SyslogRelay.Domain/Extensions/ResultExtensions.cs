using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Extensions;

public static class ResultExtensions
{
    extension<TResult>(TResult result)
        where TResult : ResultBase<TResult>
    {
        public string ErrorMessage => result.Errors.Single().Message;
    }
}
