namespace CyberAlarm.SyslogRelay.Common.EventBundler.Plugins;

/// <summary>
/// Factory interface for creating plugin instances of a specific type.
/// </summary>
/// <typeparam name="T">The type of plugin that this factory creates. Must implement <see cref="IPlugin"/>.</typeparam>
public interface IPluginFactory<out T>
    where T : IPlugin
{
    /// <summary>
    /// Creates a plugin instance based on the specified algorithm name.
    /// </summary>
    /// <param name="algorithm">The name of the algorithm that identifies which plugin implementation to create.</param>
    /// <returns>An instance of the plugin corresponding to the specified algorithm.</returns>
    /// <exception cref="ArgumentException">Thrown when the algorithm is not recognized or supported.</exception>
    T CreatePlugin(string algorithm);
}
