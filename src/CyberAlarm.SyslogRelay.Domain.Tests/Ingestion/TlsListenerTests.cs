using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Ingestion;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Ingestion;

public sealed class TlsListenerTests
{
    private readonly TlsListenerBuilder _builder = new();

    [Fact]
    public async Task StartAsync_should_throw_when_ingestAction_is_null()
    {
        var unitUnderTest = _builder.Build();

        await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await unitUnderTest.StartAsync(default!, CancellationToken.None));
    }

    [Fact]
    public async Task StartAsync_should_unregister_health_check_when_tls_is_disabled()
    {
        var options = new RelayOptionsBuilder()
            .WithTlsEnabled(false)
            .Build();

        var unitUnderTest = _builder
            .WithOptions(options)
            .Build();

        await unitUnderTest.StartAsync((syslogEvent, cancellationToken) => Task.CompletedTask, CancellationToken.None);

        await _builder.HealthToken.Received(1).UnregisterAsync(Arg.Any<CancellationToken>());
        await _builder.HealthToken.DidNotReceive().HealthyAsync(Arg.Any<CancellationToken>());
        _builder.ApplicationManager.DidNotReceive().StopApplication();
    }

    [Fact]
    public async Task StartAsync_should_throw_when_certificate_path_is_not_set_and_tls_is_enabled()
    {
        var options = new RelayOptionsBuilder()
            .WithTlsEnabled(true)
            .WithTlsCertificatePath(string.Empty)
            .Build();

        var unitUnderTest = _builder
            .WithOptions(options)
            .Build();

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await unitUnderTest.StartAsync((syslogEvent, cancellationToken) => Task.CompletedTask, CancellationToken.None));

        Assert.Equal("TLS listener is enabled but no certificate path is configured.", exception.Message);
        await _builder.HealthToken.Received(1).UnhealthyAsync(Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task StartAsync_should_throw_when_client_ca_path_is_not_set_and_mutual_tls_is_enabled()
    {
        var certificatePath = Path.GetTempFileName();

        try
        {
            var options = new RelayOptionsBuilder()
                .WithTlsEnabled(true)
                .WithTlsCertificatePath(certificatePath)
                .WithTlsRequireClientCertificate(true)
                .WithTlsClientCaCertificatePath(string.Empty)
                .Build();

            var unitUnderTest = _builder
                .WithOptions(options)
                .Build();

            var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                await unitUnderTest.StartAsync((syslogEvent, cancellationToken) => Task.CompletedTask, CancellationToken.None));

            Assert.Equal("TLS listener requires a client CA certificate path.", exception.Message);
            await _builder.HealthToken.Received(1).UnhealthyAsync(Arg.Any<CancellationToken>());
        }
        finally
        {
            File.Delete(certificatePath);
        }
    }

    [Fact]
    public async Task StartAsync_should_ingest_event_over_tls()
    {
        var port = GetAvailablePort();
        using var certificateAuthority = CreateCertificateAuthority();
        using var serverCertificate = CreateSignedCertificate(certificateAuthority, "localhost", serverAuth: true, clientAuth: false);
        var certificatePath = CreatePkcs12File(serverCertificate, "password");

        try
        {
            var options = new RelayOptionsBuilder()
                .WithTlsEnabled(true)
                .WithTlsPort(port)
                .WithTlsCertificatePath(certificatePath)
                .WithTlsCertificatePassword("password")
                .WithMaximumTcpClients(1)
                .Build();

            var unitUnderTest = _builder
                .WithOptions(options)
                .Build();

            var receivedEvent = new TaskCompletionSource<SyslogEvent>(TaskCreationOptions.RunContinuationsAsynchronously);
            using var cancellationTokenSource = new CancellationTokenSource();

            var listenerTask = Task.Run(() => unitUnderTest.StartAsync(
                (syslogEvent, cancellationToken) =>
                {
                    receivedEvent.TrySetResult(syslogEvent);
                    return Task.CompletedTask;
                },
                cancellationTokenSource.Token));

            await using var client = await ConnectTlsClientAsync(port, serverCertificate.Thumbprint!, clientCertificate: null);
            await client.WriteLineAsync("<13>Apr 24 12:00:00 localhost tls test");

            var syslogEvent = await receivedEvent.Task.WaitAsync(TimeSpan.FromSeconds(5));

            Assert.Equal(IngestionMethod.Tcp, syslogEvent.EventSource.IngestionMethod);
            Assert.Equal("<13>Apr 24 12:00:00 localhost tls test", syslogEvent.RawData);

            cancellationTokenSource.Cancel();
            await listenerTask.WaitAsync(TimeSpan.FromSeconds(5));
            await _builder.HealthToken.Received(1).HealthyAsync(Arg.Any<CancellationToken>());
        }
        finally
        {
            File.Delete(certificatePath);
        }
    }

    [Fact]
    public async Task StartAsync_should_ingest_event_over_mutual_tls()
    {
        var port = GetAvailablePort();
        using var certificateAuthority = CreateCertificateAuthority();
        using var serverCertificate = CreateSignedCertificate(certificateAuthority, "localhost", serverAuth: true, clientAuth: false);
        using var clientCertificate = CreatePersistedPkcs12Certificate(
            CreateSignedCertificate(certificateAuthority, "tls-client", serverAuth: false, clientAuth: true),
            "password");
        var certificatePath = CreatePkcs12File(serverCertificate, "password");
        var caPath = CreatePemFile(certificateAuthority);

        try
        {
            var options = new RelayOptionsBuilder()
                .WithTlsEnabled(true)
                .WithTlsPort(port)
                .WithTlsCertificatePath(certificatePath)
                .WithTlsCertificatePassword("password")
                .WithTlsRequireClientCertificate(true)
                .WithTlsClientCaCertificatePath(caPath)
                .WithMaximumTcpClients(1)
                .Build();

            var unitUnderTest = _builder
                .WithOptions(options)
                .Build();

            var receivedEvent = new TaskCompletionSource<SyslogEvent>(TaskCreationOptions.RunContinuationsAsynchronously);
            using var cancellationTokenSource = new CancellationTokenSource();

            var listenerTask = Task.Run(() => unitUnderTest.StartAsync(
                (syslogEvent, cancellationToken) =>
                {
                    receivedEvent.TrySetResult(syslogEvent);
                    return Task.CompletedTask;
                },
                cancellationTokenSource.Token));

            await using var client = await ConnectTlsClientAsync(port, serverCertificate.Thumbprint!, clientCertificate);
            await client.WriteLineAsync("<13>Apr 24 12:00:00 localhost mutual tls test");

            var syslogEvent = await receivedEvent.Task.WaitAsync(TimeSpan.FromSeconds(5));

            Assert.Equal(IngestionMethod.Tcp, syslogEvent.EventSource.IngestionMethod);
            Assert.Equal("<13>Apr 24 12:00:00 localhost mutual tls test", syslogEvent.RawData);

            cancellationTokenSource.Cancel();
            await listenerTask.WaitAsync(TimeSpan.FromSeconds(5));
        }
        finally
        {
            File.Delete(certificatePath);
            File.Delete(caPath);
        }
    }

    private static int GetAvailablePort()
    {
        using var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private static async Task<ConnectedTlsClient> ConnectTlsClientAsync(
        int port,
        string expectedServerThumbprint,
        X509Certificate2? clientCertificate)
    {
        Exception? lastException = null;

        for (var attempt = 0; attempt < 20; attempt++)
        {
            var tcpClient = new TcpClient();

            try
            {
                await tcpClient.ConnectAsync(IPAddress.Loopback, port);

                var sslStream = new SslStream(
                    tcpClient.GetStream(),
                    leaveInnerStreamOpen: false,
                    (_, certificate, _, errors) =>
                    {
                        return errors == SslPolicyErrors.None ||
                            certificate is X509Certificate2 x509Certificate &&
                            string.Equals(x509Certificate.Thumbprint, expectedServerThumbprint, StringComparison.OrdinalIgnoreCase);
                    });

                var certificates = new X509CertificateCollection();
                if (clientCertificate is not null)
                {
                    certificates.Add(clientCertificate);
                }

                await sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = "localhost",
                    ClientCertificates = certificates,
                    LocalCertificateSelectionCallback = clientCertificate is not null
                        ? (_, _, _, _, _) => clientCertificate
                        : null,
                    EnabledSslProtocols = SslProtocols.Tls12,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                });

                return new ConnectedTlsClient(tcpClient, sslStream);
            }
            catch (Exception ex) when (attempt < 19)
            {
                lastException = ex;
                tcpClient.Dispose();
                await Task.Delay(100);
            }
        }

        throw new InvalidOperationException("Failed to connect to the TLS listener.", lastException);
    }

    private static X509Certificate2 CreateCertificateAuthority()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=CyberAlarm Test CA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
    }

    private static X509Certificate2 CreateSignedCertificate(
        X509Certificate2 certificateAuthority,
        string commonName,
        bool serverAuth,
        bool clientAuth)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest($"CN={commonName}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                true));

        var usages = new OidCollection();
        if (serverAuth)
        {
            usages.Add(new Oid("1.3.6.1.5.5.7.3.1"));
        }

        if (clientAuth)
        {
            usages.Add(new Oid("1.3.6.1.5.5.7.3.2"));
        }

        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        if (serverAuth)
        {
            var subjectAlternativeNames = new SubjectAlternativeNameBuilder();
            subjectAlternativeNames.AddDnsName("localhost");
            request.CertificateExtensions.Add(subjectAlternativeNames.Build());
        }

        var serialNumber = RandomNumberGenerator.GetBytes(16);
        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = DateTimeOffset.UtcNow.AddDays(30);
        var issuerNotAfter = new DateTimeOffset(certificateAuthority.NotAfter.ToUniversalTime(), TimeSpan.Zero).AddSeconds(-1);
        if (issuerNotAfter < notAfter)
        {
            notAfter = issuerNotAfter;
        }

        var certificate = request.Create(
            certificateAuthority,
            notBefore,
            notAfter,
            serialNumber);

        return certificate.CopyWithPrivateKey(rsa);
    }

    private static string CreatePkcs12File(X509Certificate2 certificate, string password)
    {
        var filePath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.pfx");
        File.WriteAllBytes(filePath, certificate.Export(X509ContentType.Pkcs12, password));
        return filePath;
    }

    private static X509Certificate2 CreatePersistedPkcs12Certificate(X509Certificate2 certificate, string password)
    {
        using (certificate)
        {
            var bytes = certificate.Export(X509ContentType.Pkcs12, password);
            return X509CertificateLoader.LoadPkcs12(
                bytes,
                password,
                X509KeyStorageFlags.Exportable |
                X509KeyStorageFlags.PersistKeySet |
                X509KeyStorageFlags.UserKeySet);
        }
    }

    private static string CreatePemFile(X509Certificate2 certificate)
    {
        var filePath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.crt");
        File.WriteAllText(filePath, certificate.ExportCertificatePem());
        return filePath;
    }

    private sealed class ConnectedTlsClient(TcpClient tcpClient, SslStream sslStream) : IAsyncDisposable
    {
        private readonly StreamWriter _writer = new(sslStream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), 1024, leaveOpen: false)
        {
            AutoFlush = true,
            NewLine = "\n",
        };

        public Task WriteLineAsync(string value) => _writer.WriteLineAsync(value);

        public async ValueTask DisposeAsync()
        {
            await _writer.DisposeAsync();
            sslStream.Dispose();
            tcpClient.Dispose();
        }
    }
}
