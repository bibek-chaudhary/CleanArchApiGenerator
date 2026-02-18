using CleanArchApiGenerator.Application.Interfaces;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CleanArchApiGenerator.Infrastructure.Services
{
    public class DotnetCliService : IDotnetCliService
    {
        public async Task RunAsync(string workingDirectory, string arguments) {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "dotnet",
                    Arguments = arguments,
                    WorkingDirectory = workingDirectory,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                }
            };

            process.Start();

            await process.WaitForExitAsync();

            if(process.ExitCode != 0)
            {
                var error = await process.StandardError.ReadToEndAsync();
                throw new Exception($"dotnet CLI command failed with exit code {process.ExitCode}: {error}");
            }
        }
    }
}
