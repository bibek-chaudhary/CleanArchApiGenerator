using CleanArchApiGenerator.Application.Interfaces;
using CleanArchApiGenerator.Domain.Entities;
using Microsoft.AspNetCore.Mvc;

namespace CleanArchApiGenerator.API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class GenerateController : Controller
    {
        private readonly IProjectGeneratorService _generatorService;
        public GenerateController(IProjectGeneratorService generatorService)
        {
            _generatorService = generatorService;
        }

        [HttpPost]
        public async Task<IActionResult> Generate([FromBody] GeneratorConfiguration config)
        {
            if (string.IsNullOrWhiteSpace(config.ProjectName))
                return BadRequest("Project name is required.");
            try
            {
                var zipPath = await _generatorService.GenerateAsync(config);
                var fileBytes = System.IO.File.ReadAllBytes(zipPath);
                return File(fileBytes, "application/zip", $"{config.ProjectName}.zip");
            }
            catch (Exception ex)
            {
                // Log the exception (not implemented here)
                return StatusCode(500, $"An error occurred while generating the project: {ex.Message}");
            }
        }
}
