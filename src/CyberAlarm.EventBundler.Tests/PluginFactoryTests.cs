using CyberAlarm.SyslogRelay.Common.EventBundler.Plugins;
using NSubstitute;

namespace CyberAlarm.EventBundler.Tests;

public sealed class PluginFactoryTests
{
    [Fact]
    public void ConstructorWithMultiplePluginsStoresAllPlugins()
    {
        // Arrange
        var plugin1 = Substitute.For<IPlugin>();
        plugin1.AlgorithmName.Returns("algorithm1");

        var plugin2 = Substitute.For<IPlugin>();
        plugin2.AlgorithmName.Returns("algorithm2");

        // Act
        var factory = new PluginFactory<IPlugin>(plugin1, plugin2);

        // Assert
        var result1 = factory.CreatePlugin("algorithm1");
        var result2 = factory.CreatePlugin("algorithm2");
        Assert.Same(plugin1, result1);
        Assert.Same(plugin2, result2);
    }

    [Fact]
    public void ConstructorWithNoPluginsCreatesEmptyFactory()
    {
        // Arrange & Act
        var factory = new PluginFactory<IPlugin>();

        // Assert
        Assert.Throws<NotImplementedException>(() => factory.CreatePlugin("anyAlgorithm"));
    }

    [Fact]
    public void CreatePluginWithExistingAlgorithmReturnsCorrectPlugin()
    {
        // Arrange
        var plugin = Substitute.For<IPlugin>();
        plugin.AlgorithmName.Returns("testAlgorithm");

        var factory = new PluginFactory<IPlugin>(plugin);

        // Act
        var result = factory.CreatePlugin("testAlgorithm");

        // Assert
        Assert.Same(plugin, result);
    }

    [Fact]
    public void CreatePluginWithNonExistingAlgorithmThrowsNotImplementedException()
    {
        // Arrange
        var plugin = Substitute.For<IPlugin>();
        plugin.AlgorithmName.Returns("algorithm1");

        var factory = new PluginFactory<IPlugin>(plugin);

        // Act & Assert
        var exception = Assert.Throws<NotImplementedException>(() => factory.CreatePlugin("nonExistent"));
        Assert.Contains("nonExistent", exception.Message);
        Assert.Contains("The implementation of the algorithm", exception.Message);
    }

    [Fact]
    public void CreatePluginCaseSensitiveAlgorithmNameThrowsWhenCaseMismatch()
    {
        // Arrange
        var plugin = Substitute.For<IPlugin>();
        plugin.AlgorithmName.Returns("Algorithm");

        var factory = new PluginFactory<IPlugin>(plugin);

        // Act & Assert
        Assert.Throws<NotImplementedException>(() => factory.CreatePlugin("algorithm"));
    }

    [Fact]
    public void ConstructorWithSinglePluginStoresPlugin()
    {
        // Arrange
        var plugin = Substitute.For<IPlugin>();
        plugin.AlgorithmName.Returns("singleAlgorithm");

        // Act
        var factory = new PluginFactory<IPlugin>(plugin);

        // Assert
        var result = factory.CreatePlugin("singleAlgorithm");
        Assert.Same(plugin, result);
    }

    [Fact]
    public void CreatePluginReturnsConsistentInstanceWhenCalledMultipleTimes()
    {
        // Arrange
        var plugin = Substitute.For<IPlugin>();
        plugin.AlgorithmName.Returns("algorithm");

        var factory = new PluginFactory<IPlugin>(plugin);

        // Act
        var result1 = factory.CreatePlugin("algorithm");
        var result2 = factory.CreatePlugin("algorithm");

        // Assert
        Assert.Same(result1, result2);
        Assert.Same(plugin, result1);
    }
}
