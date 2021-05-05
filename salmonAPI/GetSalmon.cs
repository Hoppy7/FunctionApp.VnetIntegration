using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace FunctionAppDemo.SalmonApi
{
    public static class GetSalmon
    {
        [FunctionName("GetSalmon")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = null)] HttpRequest req,
            ExecutionContext context,
            ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");

            Salmon salmon = new Salmon();

            var json = JsonConvert.SerializeObject(salmon);

            return new OkObjectResult(json);
        }
    }

    public class Salmon
    {
        public List<string> salmonSpecies = new List<string>
        {
            "Chinook",
            "Coho",
            "Sockeye",
            "Chum",
            "Pink"
        };
    }
}