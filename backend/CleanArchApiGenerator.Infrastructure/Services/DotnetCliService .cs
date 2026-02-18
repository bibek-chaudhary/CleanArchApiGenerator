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

            var outputBuilder = new StringBuilder();
            var errorBuilder = new StringBuilder();

            process.OutputDataReceived += (sender, args) => {
                if (args.Data != null)
                    outputBuilder.AppendLine(args.Data);
            };

            process.ErrorDataReceived += (sender, args) => {
                if (args.Data != null)
                    errorBuilder.AppendLine(args.Data);
            };

            process.Start();

            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            await process.WaitForExitAsync();

            if(process.ExitCode != 0)
            {
                throw new Exception(
                $"Dotnet CLI failed.\nError:\n{errorBuilder}\nOutput:\n{outputBuilder}");
            }
        }
    }
}
