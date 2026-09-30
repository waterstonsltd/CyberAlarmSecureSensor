using System.Diagnostics.Metrics;
using Microsoft.Extensions.Diagnostics.Metrics;

namespace CyberAlarm.SyslogRelay.Tests.Common;

/// <summary>
/// A minimal <see cref="IMeterFactory"/> for use in unit tests. Creates real
/// <see cref="Meter"/> instances so instrument creation succeeds, without
/// requiring the full DI metrics pipeline.
/// </summary>
public sealed class TestMeterFactory : IMeterFactory
{
    private readonly List<Meter> _meters = [];

    public Meter Create(MeterOptions options)
    {
        var meter = new Meter(options.Name, options.Version, options.Tags);
        _meters.Add(meter);
        return meter;
    }

    public void Dispose()
    {
        foreach (var meter in _meters)
        {
            meter.Dispose();
        }

        _meters.Clear();
    }
}
