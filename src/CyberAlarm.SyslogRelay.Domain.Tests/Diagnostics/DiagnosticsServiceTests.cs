using System.Text.Json;
using CyberAlarm.SyslogRelay.Domain.Diagnostics;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Diagnostics;

public sealed class DiagnosticsServiceTests : IDisposable
{
    private readonly DiagnosticsServiceBuilder _builder = new();

    public void Dispose() => _builder.Dispose();

    [Fact]
    public async Task RunAsync_output_contains_header()
    {
        // Arrange
        var sut = _builder.Build();
        var output = new StringWriter();

        // Act
        await sut.RunAsync(output, CancellationToken.None);

        // Assert
        Assert.Contains("CyberAlarm Secure Sensor", output.ToString());
    }

    [Fact]
    public async Task RunAsync_output_contains_registration_section_header()
    {
        // Arrange
        var sut = _builder.Build();
        var output = new StringWriter();

        // Act
        await sut.RunAsync(output, CancellationToken.None);

        // Assert
        Assert.Contains("Registration & Upload State", output.ToString());
    }

    [Fact]
    public async Task RunAsync_output_contains_version_from_options()
    {
        // Arrange
        var sut = _builder.Build();
        var output = new StringWriter();

        // Act
        await sut.RunAsync(output, CancellationToken.None);

        // Assert
        Assert.Contains(_builder.RelayOptions.BuildVersion, output.ToString());
    }

    [Fact]
    public async Task RunAsync_warns_when_state_is_null()
    {
        // Arrange
        _builder.WithState(null);
        var sut = _builder.Build();
        var output = new StringWriter();

        // Act
        await sut.RunAsync(output, CancellationToken.None);

        // Assert
        Assert.Contains("not completed first-run", output.ToString());
    }

    [Fact]
    public async Task RunAsync_warns_when_upload_is_blocked()
    {
        // Arrange
        _builder.WithState(new RelayStateBuilder().WithIsUploadBlocked(true).Build());
        var sut = _builder.Build();
        var output = new StringWriter();

        // Act
        await sut.RunAsync(output, CancellationToken.None);

        // Assert
        Assert.Contains("fatal authentication", output.ToString());
    }

    [Fact]
    public async Task RunAsync_shows_upload_not_blocked_when_state_is_healthy()
    {
        // Arrange
        _builder.WithState(new RelayStateBuilder().WithIsUploadBlocked(false).Build());
        var sut = _builder.Build();
        var output = new StringWriter();

        // Act
        await sut.RunAsync(output, CancellationToken.None);

        // Assert
        var text = output.ToString();
        Assert.Contains("Upload blocked", text);
        Assert.DoesNotContain("fatal authentication", text);
    }

    [Fact]
    public async Task RunAsync_warns_when_not_registered()
    {
        // Arrange
        _builder.WithState(new RelayStateBuilder().WithIsRegistered(false).Build());
        var sut = _builder.Build();
        var output = new StringWriter();

        // Act
        await sut.RunAsync(output, CancellationToken.None);

        // Assert
        Assert.Contains("not registered", output.ToString());
    }

    [Fact]
    public async Task RunAsync_warns_when_uploads_disabled_by_server()
    {
        // Arrange
        _builder.WithStatus(new RelayStatusBuilder().WithUploadsDisabled(true).Build());
        var sut = _builder.Build();
        var output = new StringWriter();

        // Act
        await sut.RunAsync(output, CancellationToken.None);

        // Assert
        Assert.Contains("disabled by the server", output.ToString());
    }

    [Fact]
    public async Task RunAsync_shows_not_found_when_healthcheck_json_is_missing()
    {
        // Arrange — healthcheck.json does not exist in the temp dir (default)
        var sut = _builder.Build();
        var output = new StringWriter();

        // Act
        await sut.RunAsync(output, CancellationToken.None);

        // Assert
        Assert.Contains("healthcheck.json not found", output.ToString());
    }

    [Fact]
    public async Task RunAsync_reports_all_services_healthy_when_every_entry_has_integer_zero_status()
    {
        // Arrange — Status serialised as integer 0 (the real-world format from HealthStatus enum)
        var healthData = new Dictionary<string, JsonElement?>
        {
            ["ServiceA"] = BuildHealthEntryInt(0),
            ["ServiceB"] = BuildHealthEntryInt(0),
        };
        _builder.WithHealthData(healthData);
        var sut = _builder.Build();
        var output = new StringWriter();

        // Act
        await sut.RunAsync(output, CancellationToken.None);

        // Assert
        Assert.Contains("All services healthy", output.ToString());
    }

    [Fact]
    public async Task RunAsync_reports_all_services_healthy_when_every_entry_is_healthy()
    {
        // Arrange
        var healthData = new Dictionary<string, JsonElement?>
        {
            ["ServiceA"] = BuildHealthEntry("Healthy"),
            ["ServiceB"] = BuildHealthEntry("Healthy"),
        };
        _builder.WithHealthData(healthData);
        var sut = _builder.Build();
        var output = new StringWriter();

        // Act
        await sut.RunAsync(output, CancellationToken.None);

        // Assert
        Assert.Contains("All services healthy", output.ToString());
    }

    [Fact]
    public async Task RunAsync_shows_unhealthy_when_integer_status_is_nonzero()
    {
        // Arrange — Status=1 maps to "Degraded"
        var healthData = new Dictionary<string, JsonElement?>
        {
            ["MyService"] = BuildHealthEntryInt(1),
        };
        _builder.WithHealthData(healthData);
        var sut = _builder.Build();
        var output = new StringWriter();

        // Act
        await sut.RunAsync(output, CancellationToken.None);

        // Assert
        var text = output.ToString();
        Assert.Contains("MyService", text);
        Assert.DoesNotContain("All services healthy", text);
    }

    [Fact]
    public async Task RunAsync_shows_unhealthy_service_name_when_service_is_degraded()
    {
        // Arrange
        var healthData = new Dictionary<string, JsonElement?>
        {
            ["MyService"] = BuildHealthEntry("Degraded"),
        };
        _builder.WithHealthData(healthData);
        var sut = _builder.Build();
        var output = new StringWriter();

        // Act
        await sut.RunAsync(output, CancellationToken.None);

        // Assert
        var text = output.ToString();
        Assert.Contains("MyService", text);
        Assert.DoesNotContain("All services healthy", text);
    }

    [Fact]
    public async Task RunAsync_output_contains_ingest_pipeline_section_header()
    {
        // Arrange
        var sut = _builder.Build();
        var output = new StringWriter();

        // Act
        await sut.RunAsync(output, CancellationToken.None);

        // Assert
        Assert.Contains("Ingest Pipeline", output.ToString());
    }

    [Fact]
    public async Task RunAsync_output_contains_connectivity_section_header()
    {
        // Arrange
        var sut = _builder.Build();
        var output = new StringWriter();

        // Act
        await sut.RunAsync(output, CancellationToken.None);

        // Assert
        Assert.Contains("Connectivity Probes", output.ToString());
    }

    private static JsonElement BuildHealthEntry(string status)
    {
        var json = $"{{\"Timestamp\":\"{DateTime.UtcNow:O}\",\"Status\":\"{status}\"}}";
        return JsonDocument.Parse(json).RootElement;
    }

    private static JsonElement BuildHealthEntryInt(int status)
    {
        var json = $"{{\"Timestamp\":\"{DateTime.UtcNow:O}\",\"Status\":{status}}}";
        return JsonDocument.Parse(json).RootElement;
    }
}
