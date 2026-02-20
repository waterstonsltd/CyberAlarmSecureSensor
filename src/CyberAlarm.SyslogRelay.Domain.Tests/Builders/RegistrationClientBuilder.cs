using System.Net;
using CyberAlarm.SyslogRelay.Domain.Registration;
using CyberAlarm.SyslogRelay.Domain.Status;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class RegistrationClientBuilder : IDisposable
{
    private readonly RelayOptions _options = new RelayOptionsBuilder().Build();
    private readonly TestHttpClientMessageHandler _messageHandler;

    public RegistrationClientBuilder()
    {
        _messageHandler = new(() =>
            new()
            {
                StatusCode = HttpStatusCode.OK
            });

        HttpClientFactory = Substitute.For<IHttpClientFactory>();
        HttpClientFactory
            .CreateClient(Arg.Any<string>())
            .Returns(new HttpClient(_messageHandler));

        StatusService = Substitute.For<IStatusService>();
        StatusService
            .GetStatusAsync(Arg.Any<CancellationToken>())
            .Returns(new RelayStatusBuilder().Build());

        Logger = Substitute.For<ILogger<RegistrationClient>>();
    }

    public IHttpClientFactory HttpClientFactory { get; }

    public IStatusService StatusService { get; }

    public ILogger<RegistrationClient> Logger { get; }

    public RegistrationClient Build() =>
        new(HttpClientFactory, StatusService, Options.Create(_options), Logger);

    public void Dispose() => _messageHandler.Dispose();

    public RegistrationClientBuilder WithResponse(HttpResponseMessage response)
    {
        _messageHandler.ResponseFactory = () => response;
        return this;
    }

    public RegistrationClientBuilder WithResponse(Func<HttpResponseMessage> responseFactory)
    {
        _messageHandler.ResponseFactory = responseFactory;
        return this;
    }
}
