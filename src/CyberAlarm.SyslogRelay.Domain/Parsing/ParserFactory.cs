using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Parsing;

internal sealed class ParserFactory(
    IServiceProvider serviceProvider,
    ILogger<ParserFactory> logger) : IParserFactory
{
    private readonly IServiceProvider _serviceProvider = serviceProvider;
    private readonly ILogger<ParserFactory> _logger = logger;

    public IParser? Create(string name, object? config)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);

        var parser = _serviceProvider.GetKeyedService<IParser>(name);
        if (parser is null)
        {
            _logger.LogError("No parser called '{Parser}' found.", name);
            return null;
        }

        var result = parser.Initialise(config);
        if (result.IsFailed)
        {
            _logger.LogError("Parser '{Parser}' failed to initialise with config '{ParserConfig}': {ErrorMessage}", name, config, result.ErrorMessage);
            return null;
        }

        return parser;
    }
}
