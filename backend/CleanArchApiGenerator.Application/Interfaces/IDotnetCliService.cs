using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CleanArchApiGenerator.Application.Interfaces
{
    public interface IDotnetCliService
    {
        Task RunAsync(string workingDirectory, string arguments);
    }
}
