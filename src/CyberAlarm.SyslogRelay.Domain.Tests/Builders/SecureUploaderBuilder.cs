using CyberAlarm.SyslogRelay.Common.Status.Models;
using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Domain.State;
using CyberAlarm.SyslogRelay.Domain.Status;
using CyberAlarm.SyslogRelay.Domain.Upload.Infrastructure;
using CyberAlarm.SyslogRelay.Domain.Upload.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class SecureUploaderBuilder
{
    public SecureUploaderBuilder()
    {
        ApplicationManager = Substitute.For<IApplicationManager>();
        FileManager = Substitute.For<IFileManager>();
        FileManager
            .GetUploadFolder()
            .Returns("folder");
        RsaKeyProvider = Substitute.For<IRsaKeyProvider>();
        StateService = Substitute.For<IStateService>();
        SecureFtpClient = Substitute.For<ISecureFtpClient>();
        SecureFtpClient.IsConnected.Returns(call => IsClientConnected);
        SecureFtpClient
            .When(client => client.Connect())
            .Do(_ => IsClientConnected = true);
        SecureFtpClient
            .When(client => client.Disconnect())
            .Do(_ => IsClientConnected = false);
        SecureFtpClientFactory = Substitute.For<ISecureFtpClientFactory>();
        SecureFtpClientFactory
            .Create(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>())
            .Returns(SecureFtpClient);
        RelayOptions = new RelayOptions
        {
            RegistrationToken = "testBucket.testUserName.testToken"
        };
        StatusService = Substitute.For<IStatusService>();
        StatusService
            .GetStatusAsync(Arg.Any<CancellationToken>())
            .Returns(new RelayStatus
            {
                StorageAccounts = new Dictionary<string, string>
                {
                    { "testBucket", "testStorageAccount" }
                },
                CurrentVersion = string.Empty,
                HostFingerprint = string.Empty,
                MinimumSupportedVersion = string.Empty,
                RegistrationEndpoint = string.Empty,
                ServerPublicKey = string.Empty,
            });
        Logger = Substitute.For<ILogger<SecureUploader>>();
    }

    public SecureUploaderBuilder WithSecureFtpClient(ISecureFtpClient secureFtpClient)
    {
        SecureFtpClientFactory
            .Create(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>())
            .Returns(secureFtpClient);
        return this;
    }

    public SecureUploaderBuilder WithOptions(RelayOptions relayOptions)
    {
        RelayOptions = relayOptions;
        return this;
    }

    public SecureUploaderBuilder WithStorageAccounts(Dictionary<string, string> storageAccounts)
    {
        StatusService
            .GetStatusAsync(Arg.Any<CancellationToken>())
            .Returns(new RelayStatus
            {
                StorageAccounts = storageAccounts,
                CurrentVersion = string.Empty,
                HostFingerprint = string.Empty,
                MinimumSupportedVersion = string.Empty,
                RegistrationEndpoint = string.Empty,
                ServerPublicKey = string.Empty,
            });
        return this;
    }

    public bool IsClientConnected { get; set; }

    public IApplicationManager ApplicationManager { get; }

    public IFileManager FileManager { get; }

    public IRsaKeyProvider RsaKeyProvider { get; }

    public IStateService StateService { get; }

    public IStatusService StatusService { get; }

    public ISecureFtpClientFactory SecureFtpClientFactory { get; }

    public ISecureFtpClient SecureFtpClient { get; }

    public RelayOptions RelayOptions { get; private set; }

    public ILogger<SecureUploader> Logger { get; }

    public SecureUploader Build() => new(
        ApplicationManager,
        FileManager,
        RsaKeyProvider,
        StateService,
        StatusService,
        SecureFtpClientFactory,
        Options.Create(RelayOptions),
        Logger);
}
