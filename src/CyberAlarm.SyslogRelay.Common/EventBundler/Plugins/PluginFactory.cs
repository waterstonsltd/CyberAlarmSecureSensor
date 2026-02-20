namespace CyberAlarm.SyslogRelay.Common.EventBundler.Plugins;

/// <summary>
/// Factory class for creating and managing plugin instances based on algorithm names.
/// </summary>
/// <typeparam name="T">The type of plugin that this factory creates, constrained to types implementing <see cref="IPlugin"/>.</typeparam>
public sealed class PluginFactory<T> : IPluginFactory<T>
    where T : IPlugin
{
    private readonly Dictionary<string, T> _plugins = new Dictionary<string, T>();

    /// <summary>
    /// Initializes a new instance of the <see cref="PluginFactory{T}"/> class with the specified plugins.
    /// </summary>
    /// <param name="plugins">An array of plugin instances to be registered in the factory, indexed by their algorithm names.</param>
    public PluginFactory(params T[] plugins)
    {
        foreach (T plugin in plugins)
        {
            _plugins.Add(plugin.AlgorithmName, plugin);
        }
    }

    /// <summary>
    /// Retrieves a plugin instance for the specified algorithm name.
    /// </summary>
    /// <param name="algorithm">The algorithm name identifying the plugin to retrieve.</param>
    /// <returns>The plugin instance associated with the specified algorithm name.</returns>
    /// <exception cref="NotImplementedException">
    /// Thrown when no plugin implementation exists for the specified algorithm.
    /// </exception>
    public T CreatePlugin(string algorithm)
    {
        if (_plugins.TryGetValue(algorithm, out var value))
        {
            return value;
        }

        throw new NotImplementedException($"The implementation of the algorithm {algorithm} for the type {typeof(T).Name} has not been provided.");
    }
}
