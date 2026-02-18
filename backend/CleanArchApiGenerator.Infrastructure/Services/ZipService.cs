using CleanArchApiGenerator.Application.Interfaces;
using System;
using System.Collections.Generic;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CleanArchApiGenerator.Infrastructure.Services
{
    public class ZipService : IZipService
    {
        public string CreateZip(string sourcePath, string projectName)
        {
            var basePath = Path.GetDirectoryName(sourcePath)!;
            var zipPath = Path.Combine(basePath, $"{projectName}.zip");

            if (File.Exists(zipPath))
                File.Delete(zipPath);

            ZipFile.CreateFromDirectory(sourcePath, zipPath);

            return zipPath;
        }
    }
}
