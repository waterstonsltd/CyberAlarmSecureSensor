using System.Net;
using CyberAlarm.SyslogRelay.Domain.Registration;
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

        Logger = Substitute.For<ILogger<RegistrationClient>>();
    }

    public IHttpClientFactory HttpClientFactory { get; }

    public ILogger<RegistrationClient> Logger { get; }

    public RegistrationClient Build() =>
        new(HttpClientFactory, Options.Create(_options), Logger);

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
