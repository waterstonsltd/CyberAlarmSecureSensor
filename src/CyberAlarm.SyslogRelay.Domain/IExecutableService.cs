namespace CyberAlarm.SyslogRelay.Domain;

public interface IExecutableService
{
    string Name { get; }

    Task ExecuteAsync(CancellationToken cancellationToken);
}
