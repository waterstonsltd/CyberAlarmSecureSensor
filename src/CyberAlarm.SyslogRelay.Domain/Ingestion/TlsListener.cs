using System.Globalization;
using System.IO.Pipelines;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.HealthCheck;
using CyberAlarm.SyslogRelay.Domain.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Ingestion;

public sealed class TlsListener(
    IApplicationManager applicationManager,
    IHealthCheckService healthCheckService,
    IOptions<RelayOptions> options,
    ILogger<TlsListener> logger) : IDisposable
{
    private readonly IApplicationManager _applicationManager = applicationManager;
    private readonly IHealthToken _healthToken = healthCheckService.GetHealthToken(nameof(TlsListener));
    private readonly RelayOptions _options = options.Value;
    private readonly ILogger<TlsListener> _logger = logger;

    private Func<SyslogEvent, CancellationToken, Task>? _ingestAction;
    private Socket? _listener;
    private CancellationTokenSource? _cts;
    private X509Certificate2? _serverCertificate;
    private X509Certificate2? _clientCaCertificate;

    public async Task StartAsync(Func<SyslogEvent, CancellationToken, Task> ingestAction, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(ingestAction);
        _ingestAction = ingestAction;

        if (!await ValidateConfiguration(cancellationToken))
        {
            return;
        }

        _serverCertificate = LoadServerCertificate(_options.TlsCertificatePath, _options.TlsCertificatePassword, cancellationToken);
        _logger.LogInformation(
            "Loaded TLS server certificate with thumbprint {Thumbprint}.",
            _serverCertificate.Thumbprint);
        var san = _serverCertificate.Extensions
            .OfType<X509SubjectAlternativeNameExtension>()
            .FirstOrDefault();
        if (san != null)
        {
            var identities = san.EnumerateDnsNames()
                .Select(dnsName => string.Create(CultureInfo.InvariantCulture, $"DNS={dnsName}"))
                .Concat(san.EnumerateIPAddresses().Select(ipAddress => string.Create(CultureInfo.InvariantCulture, $"IP={ipAddress}")))
                .ToList();
            if (identities.Count > 0)
            {
                _logger.LogInformation(
                    "TLS server certificate identities (configure your firewalls to use one of these): {Identities}",
                    string.Join(", ", identities));
            }
        }

        if (_options.TlsRequireClientCertificate)
        {
            _clientCaCertificate = LoadTrustedCertificate(_options.TlsClientCaCertificatePath, "client CA certificate", cancellationToken);
        }

        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        _logger.LogInformation("Starting TLS listener on port {Port}.", _options.TlsPort);
        _listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        _listener.Bind(new IPEndPoint(IPAddress.Any, _options.TlsPort));
        _listener.Listen();

        _logger.LogDebug("Waiting for up to {MaximumTcpClient} TLS connections...", _options.MaximumTcpClients);
        await _healthToken.HealthyAsync(_cts.Token);

        try
        {
            var clientHandlers = new List<Task>(_options.MaximumTcpClients);

            while (!_cts.Token.IsCancellationRequested)
            {
                var client = await _listener.AcceptAsync(_cts.Token);

                SocketListenerUtilities.ClearCompletedClients(clientHandlers, _logger, "TLS client handler task failed.");

                if (clientHandlers.Count < _options.MaximumTcpClients)
                {
                    clientHandlers.Add(HandleClient(client, _cts.Token));
                }
                else
                {
                    _logger.LogWarning("[{Client}] Disconnecting due to maximum limit reached.", SocketListenerUtilities.GetIPEndPoint(client));
                    client.Shutdown(SocketShutdown.Both);
                    client.Close();
                }
            }
        }
        catch (OperationCanceledException)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                _logger.LogInformation("TLS listener was cancelled.");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error running TLS listener.");

            await _healthToken.UnhealthyAsync(_cts.Token);
            _applicationManager.StopApplication();
        }
        finally
        {
            Dispose();
            _logger.LogInformation("TLS listener stopped.");
        }
    }

    public void Dispose()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;

        _listener?.Close();
        _listener = null;

        _serverCertificate?.Dispose();
        _serverCertificate = null;

        _clientCaCertificate?.Dispose();
        _clientCaCertificate = null;
    }

    private async Task<bool> ValidateConfiguration(CancellationToken cancellationToken)
    {
        if (!_options.TlsEnabled)
        {
            await _healthToken.UnregisterAsync(cancellationToken);

            _logger.LogInformation("TLS listener is disabled.");
            return false;
        }

        if (string.IsNullOrWhiteSpace(_options.TlsCertificatePath))
        {
            await _healthToken.UnhealthyAsync(cancellationToken);

            _logger.LogError("TLS listener is enabled but no certificate path is configured.");
            throw new InvalidOperationException("TLS listener is enabled but no certificate path is configured.");
        }

        if (!File.Exists(_options.TlsCertificatePath))
        {
            await _healthToken.UnhealthyAsync(cancellationToken);

            _logger.LogError(
                "TLS listener is enabled but certificate path '{CertificatePath}' does not exist.",
                _options.TlsCertificatePath);
            throw new InvalidOperationException("TLS listener certificate path does not exist.");
        }

        if (_options.TlsRequireClientCertificate && string.IsNullOrWhiteSpace(_options.TlsClientCaCertificatePath))
        {
            await _healthToken.UnhealthyAsync(cancellationToken);

            _logger.LogError("TLS listener requires client certificates but no CA certificate path is configured.");
            throw new InvalidOperationException("TLS listener requires a client CA certificate path.");
        }

        if (_options.TlsRequireClientCertificate && !File.Exists(_options.TlsClientCaCertificatePath))
        {
            await _healthToken.UnhealthyAsync(cancellationToken);

            _logger.LogError(
                "TLS listener requires client certificates but CA certificate path '{CertificatePath}' does not exist.",
                _options.TlsClientCaCertificatePath);
            throw new InvalidOperationException("TLS listener client CA certificate path does not exist.");
        }

        return true;
    }

    private X509Certificate2 LoadServerCertificate(string path, string? password, CancellationToken cancellationToken)
    {
        try
        {
            var certificate = string.IsNullOrEmpty(password)
                ? X509CertificateLoader.LoadPkcs12FromFile(path, password: null, X509KeyStorageFlags.DefaultKeySet | X509KeyStorageFlags.Exportable)
                : X509CertificateLoader.LoadPkcs12FromFile(path, password, X509KeyStorageFlags.DefaultKeySet | X509KeyStorageFlags.Exportable);

            ValidateServerCertificate(certificate, path);
            return certificate;
        }
        catch (Exception ex)
        {
            _healthToken.UnhealthyAsync(cancellationToken).GetAwaiter().GetResult();
            throw new InvalidOperationException($"Failed to load TLS server certificate from '{path}'.", ex);
        }
    }

    private static void ValidateServerCertificate(X509Certificate2 certificate, string path)
    {
        if (!certificate.HasPrivateKey)
        {
            throw new InvalidOperationException($"TLS server certificate '{path}' must include a private key.");
        }

        var enhancedKeyUsage = certificate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .FirstOrDefault();

        if (enhancedKeyUsage is null)
        {
            throw new InvalidOperationException($"TLS server certificate '{path}' must include the Server Authentication EKU.");
        }

        var hasServerAuthentication = enhancedKeyUsage.EnhancedKeyUsages
            .Cast<Oid>()
            .Any(oid => string.Equals(oid.Value, "1.3.6.1.5.5.7.3.1", StringComparison.Ordinal));

        if (!hasServerAuthentication)
        {
            throw new InvalidOperationException($"TLS server certificate '{path}' must include the Server Authentication EKU.");
        }
    }

    private X509Certificate2 LoadTrustedCertificate(string path, string description, CancellationToken cancellationToken)
    {
        try
        {
            return X509CertificateLoader.LoadCertificateFromFile(path);
        }
        catch (Exception ex)
        {
            _healthToken.UnhealthyAsync(cancellationToken).GetAwaiter().GetResult();
            throw new InvalidOperationException($"Failed to load TLS {description} from '{path}'.", ex);
        }
    }

    private async Task HandleClient(Socket clientSocket, CancellationToken cancellationToken)
    {
        var client = SocketListenerUtilities.GetIPEndPoint(clientSocket);

        _logger.LogDebug("[{Client}] connected.", client);
        using var stream = new NetworkStream(clientSocket, ownsSocket: false);
        using var sslStream = new SslStream(
            stream,
            leaveInnerStreamOpen: true,
            ValidateRemoteCertificate);

        try
        {
            await sslStream.AuthenticateAsServerAsync(
                new SslServerAuthenticationOptions
                {
                    ServerCertificate = _serverCertificate,
                    ClientCertificateRequired = _options.TlsRequireClientCertificate,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                },
                cancellationToken);

            var reader = PipeReader.Create(sslStream);
            await SocketListenerUtilities.ReadAsync(reader, client.Address.ToString(), SyslogEvent.FromTls, _ingestAction, _logger, cancellationToken);
            await reader.CompleteAsync();
        }
        catch (OperationCanceledException)
        {
            _logger.LogDebug("[{Client}] handling cancelled.", client);
        }
        catch (AuthenticationException ex)
        {
            _logger.LogWarning(ex, "[{Client}] TLS authentication failed.", client);
        }
        catch (IOException ex)
            when (ex.InnerException is SocketException { SocketErrorCode: SocketError.ConnectionReset })
        {
            _logger.LogWarning(ex, "[{Client}] Connection reset by peer.", client);
        }
        catch (IOException ex)
        {
            // SSL/TLS alerts (e.g. handshake_failure, decrypt_error) surface as IOException
            // after the handshake completes. These are peer-side failures, not server bugs.
            _logger.LogWarning(ex, "[{Client}] TLS error reading from client.", client);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred when ingesting TLS log data from [{Client}].", client);
        }
        finally
        {
            try
            {
                clientSocket.Shutdown(SocketShutdown.Both);
            }
            catch (SocketException)
            {
                _logger.LogDebug("[{Client}] socket already closed while shutting down.", client);
            }

            clientSocket.Close();

            _logger.LogDebug("[{Client}] disconnected.", client);
        }
    }

    private bool ValidateRemoteCertificate(
        object sender,
        X509Certificate? certificate,
        X509Chain? chain,
        SslPolicyErrors sslPolicyErrors)
    {
        if (!_options.TlsRequireClientCertificate)
        {
            return true;
        }

        if (certificate is null || _clientCaCertificate is null)
        {
            return false;
        }

        using var clientCertificate = certificate as X509Certificate2 ?? new X509Certificate2(certificate);

        // Verify the client certificate was signed by the operator-supplied CA.
        using var validationChain = new X509Chain();
        validationChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        validationChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        validationChain.ChainPolicy.CustomTrustStore.Add(_clientCaCertificate);
        validationChain.ChainPolicy.ExtraStore.Add(_clientCaCertificate);
        validationChain.ChainPolicy.VerificationFlags =
            X509VerificationFlags.AllowUnknownCertificateAuthority |
            X509VerificationFlags.IgnoreEndRevocationUnknown |
            X509VerificationFlags.IgnoreRootRevocationUnknown;

        var chainBuilt = validationChain.Build(clientCertificate);
        if (chainBuilt)
        {
            // Confirm the chain's root is the expected CA, not some other trusted root.
            var root = validationChain.ChainElements[validationChain.ChainElements.Count - 1].Certificate;
            return string.Equals(root.Thumbprint, _clientCaCertificate.Thumbprint, StringComparison.OrdinalIgnoreCase);
        }

        // The chain may still be structurally valid if the only errors are
        // UntrustedRoot or RevocationUnknown — acceptable when the CA is operator-supplied.
        var onlyAllowedErrors = validationChain.ChainStatus.All(s =>
            s.Status == X509ChainStatusFlags.UntrustedRoot ||
            s.Status == X509ChainStatusFlags.RevocationStatusUnknown ||
            s.Status == X509ChainStatusFlags.OfflineRevocation);

        if (!onlyAllowedErrors)
        {
            return false;
        }

        var chainRoot = validationChain.ChainElements[validationChain.ChainElements.Count - 1].Certificate;
        return string.Equals(chainRoot.Thumbprint, _clientCaCertificate.Thumbprint, StringComparison.OrdinalIgnoreCase);
    }
}
