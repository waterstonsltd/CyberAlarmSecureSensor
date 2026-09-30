using System.Net;
using System.Security.Cryptography;
using System.Text;
using CyberAlarm.SyslogRelay.Common.Status.Models;
using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Domain.State;
using CyberAlarm.SyslogRelay.Domain.Status;
using CyberAlarm.SyslogRelay.Domain.Upload.Infrastructure;
using CyberAlarm.SyslogRelay.Domain.Upload.Services;
using CyberAlarm.SyslogRelay.Domain.Upload.Services.Channels;
using CyberAlarm.SyslogRelay.Tests.Common;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class SecureUploaderBuilder
{
    private static readonly Lazy<string> _testPrivateKeyPem = new(() =>
    {
        using var rsa = RSA.Create(1024);
        return rsa.ExportRSAPrivateKeyPem();
    });

    private string _hostFingerprint = "default test host fingerprint";
    private string? _secondaryHostFingerprint;
    private Dictionary<string, string> _storageAccounts = new()
    {
        { "testBucket", "teststorageaccount" }
    };

    public SecureUploaderBuilder()
    {
        ApplicationManager = Substitute.For<IApplicationManager>();
        FileManager = Substitute.For<IFileManager>();
        FileManager
            .GetUploadFolder()
            .Returns("folder");
        RsaKeyProvider = Substitute.For<IRsaKeyProvider>();
        RsaKeyProvider
            .GetPrivateKeyPem(Arg.Any<CancellationToken>())
            .Returns(_testPrivateKeyPem.Value);
        StateService = Substitute.For<IStateService>();
        SecureFtpClient = Substitute.For<ISecureFtpClient>();
        SecureFtpClient.IsConnected.Returns(call => IsClientConnected);
        SecureFtpClient
            .When(client => client.Connect())
            .Do(_ => IsClientConnected = true);
        SecureFtpClient
            .When(client => client.Disconnect())
            .Do(_ => IsClientConnected = false);
        Logger = Substitute.For<ILogger<SecureUploader>>();
        UploadMetrics = new UploadMetrics(new TestMeterFactory());
        SftpChannelFactory = Substitute.For<IUploadChannelFactory>();
        SftpChannelFactory
            .Create(Arg.Any<UploadContext>())
            .Returns(_ => new SftpUploadChannel(SecureFtpClient, FileManager, ApplicationManager, StateService, UploadMetrics, Logger));
        RelayOptions = new RelayOptions
        {
            RegistrationToken = "testBucket.testUserName.testToken",
            ApiBaseUrl = "https://test-api.example.com"
        };
        StatusService = Substitute.For<IStatusService>();
        StatusService
            .GetStatusAsync(Arg.Any<CancellationToken>())
            .Returns(_ => new RelayStatus
            {
                StorageAccounts = _storageAccounts,
                CurrentVersion = string.Empty,
                HostFingerprint = _hostFingerprint,
                SecondaryHostFingerprint = _secondaryHostFingerprint,
                MinimumSupportedVersion = string.Empty,
                ServerPublicKey = string.Empty,
            });
        HttpMessageHandler = new CapturingHttpMessageHandler();
        var fakeHttpClientFactory = Substitute.For<IHttpClientFactory>();
        fakeHttpClientFactory
            .CreateClient(Arg.Any<string>())
            .Returns(new HttpClient(HttpMessageHandler));
        HttpsSasChannelFactory = Substitute.For<IUploadChannelFactory>();
        HttpsSasChannelFactory
            .Create(Arg.Any<UploadContext>())
            .Returns(callInfo => new HttpsSasUploadChannel(
                fakeHttpClientFactory,
                callInfo.ArgAt<UploadContext>(0),
                FileManager,
                ApplicationManager,
                StateService,
                UploadMetrics,
                Logger));
    }

    public SecureUploaderBuilder WithSecureFtpClient(ISecureFtpClient secureFtpClient)
    {
        SftpChannelFactory
            .Create(Arg.Any<UploadContext>())
            .Returns(_ => new SftpUploadChannel(secureFtpClient, FileManager, ApplicationManager, StateService, UploadMetrics, Logger));
        return this;
    }

    public SecureUploaderBuilder WithOptions(RelayOptions relayOptions)
    {
        RelayOptions = relayOptions;
        return this;
    }

    public SecureUploaderBuilder WithStorageAccounts(Dictionary<string, string> storageAccounts)
    {
        _storageAccounts = storageAccounts;
        return this;
    }

    public SecureUploaderBuilder WithHostFingerprint(string hostFingerprint)
    {
        _hostFingerprint = hostFingerprint;
        return this;
    }

    public SecureUploaderBuilder WithSecondaryHostFingerprint(string secondaryHostFingerprint)
    {
        _secondaryHostFingerprint = secondaryHostFingerprint;
        return this;
    }

    public SecureUploaderBuilder WithHttpResponse(HttpStatusCode statusCode, string? jsonContent = null)
    {
        HttpMessageHandler.Enqueue(new HttpResponseMessage(statusCode)
        {
            Content = jsonContent is null
                ? null
                : new StringContent(jsonContent, Encoding.UTF8, "application/json")
        });
        return this;
    }

    public bool IsClientConnected { get; set; }

    public IApplicationManager ApplicationManager { get; }

    public IFileManager FileManager { get; }

    public IRsaKeyProvider RsaKeyProvider { get; }

    public IStateService StateService { get; }

    public IStatusService StatusService { get; }

    public ISecureFtpClient SecureFtpClient { get; }

    public IUploadChannelFactory SftpChannelFactory { get; }

    public IUploadChannelFactory HttpsSasChannelFactory { get; }

    public CapturingHttpMessageHandler HttpMessageHandler { get; }

    public UploadMetrics UploadMetrics { get; }

    public RelayOptions RelayOptions { get; private set; }

    public ILogger<SecureUploader> Logger { get; }

    public SecureUploader Build() => new(
        FileManager,
        RsaKeyProvider,
        StatusService,
        [SftpChannelFactory, HttpsSasChannelFactory],
        Options.Create(RelayOptions),
        UploadMetrics,
        Logger);
}

internal sealed class CapturingHttpMessageHandler : HttpMessageHandler
{
    private readonly Queue<HttpResponseMessage> _queue = new();

    public List<HttpRequestMessage> CapturedRequests { get; } = [];

    public void Enqueue(HttpResponseMessage response) => _queue.Enqueue(response);

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        CapturedRequests.Add(request);
        return Task.FromResult(
            _queue.TryDequeue(out var response)
                ? response
                : new HttpResponseMessage(HttpStatusCode.OK));
    }
}
