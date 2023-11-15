using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;

namespace az_webhook_test
{
    public static class HttpTrigger1
    {
        [FunctionName("webhook")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = null)] HttpRequest req, ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request");

            const string secretKey = "{PUT YOUR SECRET KEY HERE}}";
            if (!req.Headers.TryGetValue("x-h4b-hmac-sha256", out var hmacHeader))
                return new BadRequestObjectResult("Missing x-h4b-hmac-sha256 header");

            using var reader = new StreamReader(req.Body);
            var content = await reader.ReadToEndAsync();
            var hash = ComputeHmacsha256(content, secretKey);

            if (hash == hmacHeader)
            {
                log.LogInformation("Notification Request from n1co Business received: " + content);
                return new OkResult();
            }

            log.LogInformation("Could not validate signature: " + hash);
            return new BadRequestObjectResult("Could not validate signature");
        }

        private static string ComputeHmacsha256(string content, string secret)
        {
            var secretBytes = Encoding.UTF8.GetBytes(secret);
            var contentBytes = Encoding.UTF8.GetBytes(content);

            using var hmac = new HMACSHA256(secretBytes);
            var hashBytes = hmac.ComputeHash(contentBytes);
            return Convert.ToBase64String(hashBytes);
        }
    }
}
