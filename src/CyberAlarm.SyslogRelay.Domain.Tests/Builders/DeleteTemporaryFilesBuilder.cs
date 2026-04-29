using System;
using System.Collections.Generic;
using System.Text;
using CyberAlarm.SyslogRelay.Domain.Initialisation;
using CyberAlarm.SyslogRelay.Domain.Services;
using Microsoft.Extensions.Logging;
using NSubstitute;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class DeleteTemporaryFilesBuilder
{
    private IFileManager _fileManager = Substitute.For<IFileManager>();
    private ILogger<DeleteTemporaryFiles> _logger = Substitute.For<ILogger<DeleteTemporaryFiles>>();
    private string _temporaryFolder = "C:\\Temp";
    private IEnumerable<string> _files = [];

    public DeleteTemporaryFilesBuilder WithFileManager(IFileManager fileManager)
    {
        _fileManager = fileManager;
        return this;
    }

    public DeleteTemporaryFilesBuilder WithLogger(ILogger<DeleteTemporaryFiles> logger)
    {
        _logger = logger;
        return this;
    }

    public DeleteTemporaryFilesBuilder WithTemporaryFolder(string folder)
    {
        _temporaryFolder = folder;
        _fileManager.GetTemporaryFolder().Returns(_temporaryFolder);
        return this;
    }

    public DeleteTemporaryFilesBuilder WithFiles(params string[] files)
    {
        _files = files;
        _fileManager.ListFilesInDirectory(_temporaryFolder).Returns(_files);
        return this;
    }

    public DeleteTemporaryFilesBuilder WithDeleteException(string filePath, Exception exception)
    {
        _fileManager.When(x => x.Delete(filePath)).Do(_ => throw exception);
        return this;
    }

    public DeleteTemporaryFiles Build()
    {
        _fileManager.GetTemporaryFolder().Returns(_temporaryFolder);
        _fileManager.ListFilesInDirectory(_temporaryFolder).Returns(_files);
        return new DeleteTemporaryFiles(_fileManager, _logger);
    }
}
