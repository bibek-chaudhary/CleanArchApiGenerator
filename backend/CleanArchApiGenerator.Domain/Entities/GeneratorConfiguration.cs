using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CleanArchApiGenerator.Domain.Entities
{
    public class GeneratorConfiguration
    {
        public string ProjectName { get; set; } = string.Empty;
        public bool IncludeIdentity { get; set; }
        public bool IncludeJwt { get; set; }
        public bool IncludeSqlServer { get; set; }
    }
}
