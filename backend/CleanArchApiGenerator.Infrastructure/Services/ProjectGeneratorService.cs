using CleanArchApiGenerator.Application.Interfaces;
using CleanArchApiGenerator.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CleanArchApiGenerator.Infrastructure.Services
{
    public class ProjectGeneratorService : IProjectGeneratorService
    {
        private readonly IDotnetCliService _cliService;
        private readonly IZipService _zipService;

        public ProjectGeneratorService(IDotnetCliService cliService, IZipService zipService)
        {
            _cliService = cliService;
            _zipService = zipService;
        }

        public async Task<string> GenerateAsync(GeneratorConfiguration config) {
            var basePath = Path.Combine(Directory.GetParent(Directory.GetCurrentDirectory())!.FullName, "GeneratedProjects");

            if (!Directory.Exists(basePath))
                Directory.CreateDirectory(basePath);

            var projectRoot = Path.Combine(basePath, config.ProjectName);

            if(Directory.Exists(projectRoot))
                Directory.Delete(projectRoot, true);

            Directory.CreateDirectory(projectRoot);

            // create solution
            await _cliService.RunAsync(projectRoot, $"new sln -n {config.ProjectName}");

            // create projects
            await _cliService.RunAsync(projectRoot,
           $"new webapi -n {config.ProjectName}.API");

            await _cliService.RunAsync(projectRoot,
                $"new classlib -n {config.ProjectName}.Application");

            await _cliService.RunAsync(projectRoot,
                $"new classlib -n {config.ProjectName}.Domain");

            await _cliService.RunAsync(projectRoot,
                $"new classlib -n {config.ProjectName}.Infrastructure");

            string[] classLibs = { "Domain", "Application", "Infrastructure" };
            foreach (var lib in classLibs)
            {
                var class1Path = Path.Combine(basePath, config.ProjectName, $"{config.ProjectName}.{lib}", "Class1.cs");
                if (File.Exists(class1Path))
                    File.Delete(class1Path);
            }

            // add projects to solution
            await _cliService.RunAsync(projectRoot,
            $"sln add {config.ProjectName}.API/{config.ProjectName}.API.csproj");

            await _cliService.RunAsync(projectRoot,
                $"sln add {config.ProjectName}.Application/{config.ProjectName}.Application.csproj");

            await _cliService.RunAsync(projectRoot,
                $"sln add {config.ProjectName}.Domain/{config.ProjectName}.Domain.csproj");

            await _cliService.RunAsync(projectRoot,
                $"sln add {config.ProjectName}.Infrastructure/{config.ProjectName}.Infrastructure.csproj");

            // add project references
            var apiPath = Path.Combine(projectRoot, $"{config.ProjectName}.API");
            var appPath = Path.Combine(projectRoot, $"{config.ProjectName}.Application");
            var infraPath = Path.Combine(projectRoot, $"{config.ProjectName}.Infrastructure");

            await _cliService.RunAsync(apiPath,
                $"add reference ../{config.ProjectName}.Application/{config.ProjectName}.Application.csproj");

            await _cliService.RunAsync(apiPath,
                $"add reference ../{config.ProjectName}.Infrastructure/{config.ProjectName}.Infrastructure.csproj");

            await _cliService.RunAsync(infraPath,
                $"add reference ../{config.ProjectName}.Application/{config.ProjectName}.Application.csproj");

            await _cliService.RunAsync(infraPath,
                $"add reference ../{config.ProjectName}.Domain/{config.ProjectName}.Domain.csproj");

            await _cliService.RunAsync(appPath,
                $"add reference ../{config.ProjectName}.Domain/{config.ProjectName}.Domain.csproj");

            // Restore packages
            await _cliService.RunAsync(projectRoot, "restore");

            // Build solution
            await _cliService.RunAsync(projectRoot, "build");

            //zip and return path
            return _zipService.CreateZip(projectRoot, config.ProjectName);
        }
    }
}
