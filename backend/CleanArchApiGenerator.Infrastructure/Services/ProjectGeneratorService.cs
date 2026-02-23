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

            await _cliService.RunAsync(apiPath,
                "add package Microsoft.AspNetCore.Authentication.JwtBearer --version 8.0.24");

            await _cliService.RunAsync(apiPath,
                "add package FluentValidation.AspNetCore");

            await _cliService.RunAsync(appPath,
                "add package FluentValidation");

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

            // create jwt token service
            CreateJwtTokenService(projectRoot, config.ProjectName);

            // create auth controller
            CreateAuthController(projectRoot, config.ProjectName);

            // create api error response
            CreateApiErrorResponse(projectRoot, config.ProjectName);

            // create exception middleware
            CreateExceptionMiddleware(projectRoot, config.ProjectName);

            // create middleware extension
            CreateMiddlewareExtensions(projectRoot, config.ProjectName);

            // create login request dto
            CreateLoginRequest(projectRoot, config.ProjectName);

            // create fluent validation
            CreateFluentValidation(projectRoot, config.ProjectName);

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
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using FluentValidation;
using FluentValidation.AspNetCore;
using System.Reflection;
using {projectName}.Infrastructure;
using {projectName}.API.Middleware;
using {projectName}.Application.Validators;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddInfrastructure(builder.Configuration);

var jwtSettings = builder.Configuration.GetSection(""Jwt"");

builder.Services.AddAuthentication(options =>
{{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}})
.AddJwtBearer(options =>
{{
    options.TokenValidationParameters = new TokenValidationParameters
    {{
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,

        ValidIssuer = jwtSettings[""Issuer""],
        ValidAudience = jwtSettings[""Audience""],
        IssuerSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(jwtSettings[""Key""]!))
    }};
}});

builder.Services.AddFluentValidationAutoValidation();
builder.Services.AddFluentValidationClientsideAdapters();

builder.Services.AddValidatorsFromAssemblyContaining<LoginRequestValidator>();

var app = builder.Build();

app.UseGlobalExceptionHandling();

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
using {projectName}.Infrastructure.Identity;
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

        services.AddScoped<JwtTokenService>();

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
   ""Jwt"": {{
    ""Key"": ""THIS_IS_A_SUPER_SECRET_KEY_CHANGE_IT"",
    ""Issuer"": ""CleanArchApi"",
    ""Audience"": ""CleanArchApiUsers"",
    ""ExpiryMinutes"": 60
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

        private void CreateJwtTokenService(string projectRoot, string projectName)
        {
            var identityFolder = Path.Combine(
                projectRoot,
                $"{projectName}.Infrastructure",
                "Identity");

            Directory.CreateDirectory(identityFolder);

            var content = $@"
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using {projectName}.Domain.Entities;
using System.IdentityModel.Tokens.Jwt;

namespace {projectName}.Infrastructure.Identity;

public class JwtTokenService
{{
    private readonly IConfiguration _configuration;

    public JwtTokenService(IConfiguration configuration)
    {{
        _configuration = configuration;
    }}

    public string GenerateToken(ApplicationUser user)
    {{
        var jwtSettings = _configuration.GetSection(""Jwt"");

        var claims = new List<Claim>
        {{
            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
            new Claim(JwtRegisteredClaimNames.Email, user.Email ?? """"),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        }};

        var key = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(jwtSettings[""Key""]!));

        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var expires = DateTime.UtcNow.AddMinutes(
            double.Parse(jwtSettings[""ExpiryMinutes""]!));

        var token = new JwtSecurityToken(
            issuer: jwtSettings[""Issuer""],
            audience: jwtSettings[""Audience""],
            claims: claims,
            expires: expires,
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }}
}}
";

            File.WriteAllText(
                Path.Combine(identityFolder, "JwtTokenService.cs"),
                content);
        }

        private void CreateAuthController(string projectRoot, string projectName)
        {
            var controllerFolder = Path.Combine(projectRoot, $"{projectName}.API", "Controllers");
            var content = $@"
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using {projectName}.Infrastructure.Identity;
using {projectName}.Domain.Entities;
using {projectName}.Application.DTOs.Auth;

namespace {projectName}.API.Controllers;

public class AuthController : BaseApiController
{{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly JwtTokenService _tokenService;

    public AuthController(
        UserManager<ApplicationUser> userManager,
        JwtTokenService tokenService)
    {{
        _userManager = userManager;
        _tokenService = tokenService;
    }}

    [HttpPost(""register"")]
    public async Task<IActionResult> Register(string email, string password)
    {{
        var user = new ApplicationUser
        {{
            UserName = email,
            Email = email
        }};

        var result = await _userManager.CreateAsync(user, password);

        if (!result.Succeeded)
            return BadRequest(result.Errors);

        return Ok(""User registered"");
    }}

    [HttpPost(""login"")]
    public async Task<IActionResult> Login(LoginRequest request)
    {{
        var user = await _userManager.FindByEmailAsync(request.Email);

        if (user == null ||
            !await _userManager.CheckPasswordAsync(user, request.Password))
            return Unauthorized();

        var token = _tokenService.GenerateToken(user);

        return Ok(new {{ token }});
    }}
}}
";
            File.WriteAllText(
                Path.Combine(controllerFolder, "AuthController.cs"),
                content);

        }

        private void CreateApiErrorResponse(string projectRoot, string projectName)
        {
            var commonFolder = Path.Combine(projectRoot, $"{projectName}.API", "Common");

            Directory.CreateDirectory(commonFolder);

            var content = $@"
namespace {projectName}.API.Common;

public class ApiErrorResponse
{{
    public bool Success {{ get; set; }} = false;
    public string Message {{ get; set; }} = ""An error occurred."";
    public object? Errors {{ get; set; }}
}}
";

            File.WriteAllText(Path.Combine(commonFolder, "ApiErrorResponse.cs"), content);
        }

        private void CreateExceptionMiddleware(string projectRoot, string projectName)
        {
            var middlewareFolder = Path.Combine(projectRoot, $"{projectName}.API", "Middleware");

            Directory.CreateDirectory(middlewareFolder);

            var content = $@"
using System.Net;
using System.Text.Json;
using {projectName}.API.Common;

namespace {projectName}.API.Middleware;

public class ExceptionMiddleware
{{
    private readonly RequestDelegate _next;
    private readonly ILogger<ExceptionMiddleware> _logger;

    public ExceptionMiddleware(
        RequestDelegate next,
        ILogger<ExceptionMiddleware> logger)
    {{
        _next = next;
        _logger = logger;
    }}

    public async Task InvokeAsync(HttpContext context)
    {{
        try
        {{
            await _next(context);
        }}
        catch (Exception ex)
        {{
            _logger.LogError(ex, ""Unhandled exception occurred."");

            await HandleExceptionAsync(context, ex);
        }}
    }}

    private static async Task HandleExceptionAsync(
        HttpContext context,
        Exception exception)
    {{
        var response = context.Response;
        response.ContentType = ""application/json"";

        var apiError = new ApiErrorResponse();

        switch (exception)
        {{
            case UnauthorizedAccessException:
                response.StatusCode = (int)HttpStatusCode.Unauthorized;
                apiError.Message = ""Unauthorized access."";
                break;

            case ArgumentException:
                response.StatusCode = (int)HttpStatusCode.BadRequest;
                apiError.Message = exception.Message;
                break;

            default:
                response.StatusCode = (int)HttpStatusCode.InternalServerError;
                apiError.Message = ""Internal server error."";
                break;
        }}

        var json = JsonSerializer.Serialize(apiError);

        await response.WriteAsync(json);
    }}
}}
";

            File.WriteAllText(Path.Combine(middlewareFolder, "ExceptionMiddleware.cs"), content);
        }

        private void CreateMiddlewareExtensions(string projectRoot, string projectName)
        {
            var middlewareFolder = Path.Combine(
                projectRoot,
                $"{projectName}.API",
                "Middleware");

            var content = $@"
namespace {projectName}.API.Middleware;

public static class MiddlewareExtensions
{{
    public static IApplicationBuilder UseGlobalExceptionHandling(
        this IApplicationBuilder app)
    {{
        return app.UseMiddleware<ExceptionMiddleware>();
    }}
}}
";

            File.WriteAllText(
                Path.Combine(middlewareFolder, "MiddlewareExtensions.cs"),
                content);
        }

        private void CreateLoginRequest(string projectRoot, string projectName)
        {
            var authFolder = Path.Combine(projectRoot, $"{projectName}.Application", "DTOs","Auth");
            Directory.CreateDirectory(authFolder);
            var content = $@"
namespace {projectName}.Application.DTOs.Auth
{{
    public class LoginRequest
    {{
        public string Email {{ get; set; }} = default!;
        public string Password {{ get; set; }} = default!;
    }}
}}
";

            File.WriteAllText(
                Path.Combine(authFolder, "LoginRequest.cs"),
                content);
        }

        private void CreateFluentValidation(string projectRoot, string projectName)
        {
            var validatorsFolder = Path.Combine(projectRoot, $"{projectName}.Application", "Validators");
            Directory.CreateDirectory(validatorsFolder);
            var content = $@"
using FluentValidation;
using {projectName}.Application.DTOs.Auth;

namespace {projectName}.Application.Validators
{{
    public class LoginRequestValidator : AbstractValidator<LoginRequest>
    {{
        public LoginRequestValidator()
        {{
            RuleFor(x => x.Email)
                .NotEmpty()
                .EmailAddress();

            RuleFor(x => x.Password)
                .NotEmpty()
                .MinimumLength(6);
        }}
    }}
}}

";

            File.WriteAllText(
                Path.Combine(validatorsFolder, "LoginRequestValidator.cs"),
                content);
        }
    }
}
