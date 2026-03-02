namespace CyberAlarm.SyslogRelay.Domain.Tests;

public sealed class TestHttpClientMessageHandler(Func<HttpResponseMessage> responseFactory) : HttpMessageHandler
{
    public Func<HttpResponseMessage> ResponseFactory { get; set; } = responseFactory;

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
        Task.FromResult(ResponseFactory());
}
