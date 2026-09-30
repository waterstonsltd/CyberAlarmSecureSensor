namespace CyberAlarm.SyslogRelay.Common.EventBundler.Plugins;

/// <summary>
/// Defines the contract for plugin implementations that provide event bundling algorithms.
/// </summary>
public interface IPlugin
{
    /// <summary>
    /// Gets the name of the algorithm implemented by this plugin.
    /// </summary>
    /// <value>
    /// A string representing the unique identifier or name of the bundling algorithm.
    /// </value>
    string AlgorithmName { get; }
}
