using CleanArchApiGenerator.Application.Interfaces;
using CleanArchApiGenerator.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Serialization;

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
                $"new webapi -n {config.ProjectName}.API -f net8.0");

            await _cliService.RunAsync(projectRoot,
                $"new classlib -n {config.ProjectName}.Application -f net8.0");

            await _cliService.RunAsync(projectRoot,
                $"new classlib -n {config.ProjectName}.Domain -f net8.0");

            await _cliService.RunAsync(projectRoot,
                $"new classlib -n {config.ProjectName}.Infrastructure -f net8.0");

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
            var domainPath = Path.Combine(projectRoot, $"{config.ProjectName}.Domain");
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

            // addd required nuget packages
            await _cliService.RunAsync(infraPath,
                "add package Microsoft.EntityFrameworkCore --version 8.0.24");

            await _cliService.RunAsync(infraPath,
                "add package Microsoft.EntityFrameworkCore.SqlServer --version 8.0.24");

            await _cliService.RunAsync(infraPath,
                "add package Microsoft.EntityFrameworkCore.Tools --version 8.0.24");

            await _cliService.RunAsync(infraPath,
                "add package Microsoft.AspNetCore.Identity.EntityFrameworkCore --version 8.0.24");

            await _cliService.RunAsync(infraPath,
               "add package Microsoft.AspNetCore.Identity");

            await _cliService.RunAsync(apiPath,
                "add package Microsoft.EntityFrameworkCore.Design --version 8.0.24");

            await _cliService.RunAsync(domainPath,
                "add package Microsoft.AspNetCore.Identity.EntityFrameworkCore --version 8.0.24");

            // clean api project
            CleanApiProject(projectRoot, config.ProjectName);

            // add dbContext
            CreateDbContext(projectRoot, config.ProjectName);

            // add infrastructure dependency injection
            CreateInfrastructureDI(projectRoot, config.ProjectName);

            // add default sql server connection string
            UpdateAppSettings(projectRoot, config.ProjectName);

            // create application user
            CreateApplicationUser(projectRoot, config.ProjectName);

            // Restore packages
            await _cliService.RunAsync(projectRoot, "restore");

            // Build solution
            await _cliService.RunAsync(projectRoot, "build");

            // migrations and database update
            await _cliService.RunAsync(
                projectRoot,
                $"ef migrations add InitialCreate --project {config.ProjectName}.Infrastructure --startup-project {config.ProjectName}.API --output-dir Persistence/Migrations");

            await _cliService.RunAsync(
                projectRoot,
                $"ef database update --project {config.ProjectName}.Infrastructure --startup-project {config.ProjectName}.API");


            //zip and return path
            return _zipService.CreateZip(projectRoot, config.ProjectName);
        }

        private void CleanApiProject(string projectRoot, string projectName)
        {
            var apiPath = Path.Combine(projectRoot, $"{projectName}.API");

            // Ensure API project exists
            if (!Directory.Exists(apiPath))
                throw new DirectoryNotFoundException($"API project not found: {apiPath}");

            // Remove WeatherForecast model
            var weatherModel = Path.Combine(apiPath, "WeatherForecast.cs");
            if (File.Exists(weatherModel))
                File.Delete(weatherModel);

            // Remove WeatherForecast controller
            var weatherController = Path.Combine(apiPath, "Controllers", "WeatherForecastController.cs");
            if (File.Exists(weatherController))
                File.Delete(weatherController);

            // Ensure Controllers folder exists
            var controllerFolder = Path.Combine(apiPath, "Controllers");
            Directory.CreateDirectory(controllerFolder);

            // Replace Program.cs
            var programPath = Path.Combine(apiPath, "Program.cs");

            var programContent = $@"
using Microsoft.AspNetCore.Mvc;
using {projectName}.Infrastructure;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddInfrastructure(builder.Configuration);

var app = builder.Build();

if (app.Environment.IsDevelopment())
{{
    app.UseSwagger();
    app.UseSwaggerUI();
}}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
";

             File.WriteAllText(programPath, programContent);

            // Create BaseApiController
            var baseControllerPath = Path.Combine(controllerFolder, "BaseApiController.cs");

            var baseControllerContent = $@"
using Microsoft.AspNetCore.Mvc;

namespace {projectName}.API.Controllers;

[ApiController]
[Route(""api/[controller]"")]
public abstract class BaseApiController : ControllerBase
{{
}}
";

            File.WriteAllText(baseControllerPath, baseControllerContent);
        }

        private void CreateDbContext(string projectRoot, string projectName)
        {
            var infrastructurePath = Path.Combine(projectRoot, $"{projectName}.Infrastructure");
            var persistenceFolder = Path.Combine(infrastructurePath, "Persistence");

            Directory.CreateDirectory(persistenceFolder);

            var dbContextContent = $@"
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using {projectName}.Domain.Entities;

namespace {projectName}.Infrastructure.Persistence;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {{
    }}

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {{
        base.OnModelCreating(modelBuilder);
    }}
}}
";

            File.WriteAllText(
                Path.Combine(persistenceFolder, "ApplicationDbContext.cs"),
                dbContextContent);
        }

        private void CreateInfrastructureDI(string projectRoot, string projectName)
        {
            var infrastructurePath = Path.Combine(projectRoot, $"{projectName}.Infrastructure");

            var content = $@"
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using {projectName}.Domain.Entities;
using {projectName}.Infrastructure.Persistence;

namespace {projectName}.Infrastructure;

public static class DependencyInjection
{{
    public static IServiceCollection AddInfrastructure(
        this IServiceCollection services,
        IConfiguration configuration)
    {{
        services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(
                configuration.GetConnectionString(""DefaultConnection"")));

        services.AddIdentity<ApplicationUser, IdentityRole>()
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();

        return services;
    }}
}}
";

            File.WriteAllText(
                Path.Combine(infrastructurePath, "DependencyInjection.cs"),
                content);
        }

        private void UpdateAppSettings(string projectRoot, string projectName)
        {
            var apiPath = Path.Combine(projectRoot, $"{projectName}.API");
            var appSettingsPath = Path.Combine(apiPath, "appsettings.json");

            var content = $@"
{{
  ""ConnectionStrings"": {{
    ""DefaultConnection"": ""Server=localhost\\SQLEXPRESS;Database={projectName}Db;Trusted_Connection=True;TrustServerCertificate=True;""
  }},
  ""Logging"": {{
    ""LogLevel"": {{
      ""Default"": ""Information"",
      ""Microsoft.AspNetCore"": ""Warning""
    }}
  }},
  ""AllowedHosts"": ""*""
}}
";

            File.WriteAllText(appSettingsPath, content);
        }

        private void CreateApplicationUser(string projectRoot, string projectName)
        {
            var identityFolder = Path.Combine(projectRoot, $"{projectName}.Domain", "Entities");

            Directory.CreateDirectory(identityFolder);

            var content = $@"
using Microsoft.AspNetCore.Identity;

namespace {projectName}.Domain.Entities;

public class ApplicationUser : IdentityUser
{{
    public string? FirstName {{ get; set; }}
    public string? LastName {{ get; set; }}
}}
";
            File.WriteAllText(
        Path.Combine(identityFolder, "ApplicationUser.cs"),
        content);
        }
    }
}
