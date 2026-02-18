using CleanArchApiGenerator.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CleanArchApiGenerator.Application.Interfaces
{
    public interface IProjectGeneratorService
    {
        Task<string> GenerateAsync(GeneratorConfiguration config);
    }
}
