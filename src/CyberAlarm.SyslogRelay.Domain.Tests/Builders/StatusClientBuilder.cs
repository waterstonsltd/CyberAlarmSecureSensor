using System.Net;
using CyberAlarm.SyslogRelay.Domain.Status;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class StatusClientBuilder : IDisposable
{
    private readonly RelayOptions _options = new RelayOptionsBuilder().Build();
    private readonly TestHttpClientMessageHandler _messageHandler;

    public StatusClientBuilder()
    {
        _messageHandler = new(() =>
            new()
            {
                StatusCode = HttpStatusCode.OK,
                Content = new RelayStatusBuilder().Build().ToJsonStringContent(),
            });

        HttpClientFactory = Substitute.For<IHttpClientFactory>();
        HttpClientFactory
            .CreateClient(Arg.Any<string>())
            .Returns(new HttpClient(_messageHandler));

        Logger = Substitute.For<ILogger<StatusClient>>();
    }

    public IHttpClientFactory HttpClientFactory { get; }

    public ILogger<StatusClient> Logger { get; }

    public StatusClient Build() =>
        new(HttpClientFactory, Options.Create(_options), Logger);

    public void Dispose() => _messageHandler.Dispose();

    public StatusClientBuilder WithResponse(HttpResponseMessage response)
    {
        _messageHandler.ResponseFactory = () => response;
        return this;
    }
}
