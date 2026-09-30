using System.Diagnostics.CodeAnalysis;
using CyberAlarm.SyslogRelay.Common.EventBundler.Models;
using CyberAlarm.SyslogRelay.Common.EventBundler.Settings;

namespace CyberAlarm.EventBundler.Services;

/// <summary>
/// Provides services for bundling events with encryption, compression, and signing capabilities.
/// </summary>
public interface IEventBundlerService
{
    /// <summary>
    /// Bundles events into an encrypted, compressed, and signed event bundle.
    /// </summary>
    /// <param name="outputBundle">The output stream where the final event bundle will be written.</param>
    /// <param name="data">The events to bundle.</param>
    /// <param name="relayId">The unique identifier of the relay.</param>
    /// <param name="buildVersion">The build version of the relay.</param>
    /// <param name="eventsMetaData">The metadata and statistics for the events to be bundled.</param>
    /// <param name="platform">The platform on which the relay is running.</param>
    /// <param name="syslogRelayPrivateKey">The RSA private key of the syslog relay used for signing.</param>
    /// <param name="serverPublicKey">The RSA public key of the server used for encryption.</param>
    /// <param name="options">Options specifying compression, encryption, and signing algorithms.</param>
    /// <param name="cancellationToken">A token to monitor for cancellation requests.</param> 
    /// <returns>A task that represents the asynchronous operation.</returns>
    [SuppressMessage("Critical Code Smell", "S107:Methods should not have too many parameters", Justification = "All 10 parameters are distinct: input/output streams, relay metadata (id, version, events metadata, platform), cryptographic keys (private/public), bundle options, and cancellation token. A parameter object would add a type with no semantic meaning.")]
    Task<EventBundle> BundleAsync(Stream outputBundle, Stream data, string relayId, string buildVersion, EventsMetaData eventsMetaData, Platform platform, byte[] syslogRelayPrivateKey, byte[] serverPublicKey, BundleOptions options, CancellationToken cancellationToken);

}
