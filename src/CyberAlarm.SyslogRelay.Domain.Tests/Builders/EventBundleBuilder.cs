using CyberAlarm.SyslogRelay.Common.EventBundler.Models;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class EventBundleBuilder
{
    public static EventBundle Build() => new(
        new Envelope("test version", new Signature("test algorithm")),
        new Document(
            "test version",
            new RelayMetaData("test id", "test version", new Platform("test os", "test runtime", "test architecture"), "test public key"),
            new Server("test public key"),
            new Encryption([], "test key encryption algorithm", "test data encryption algorithm", "test compression algorithm"),
            DateTime.UtcNow,
            []));
}
