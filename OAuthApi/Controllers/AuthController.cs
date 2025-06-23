using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OAuthApi.Interfaces;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace OAuthApi.Controllers
{
    [ApiController]
    [Route("oauth")]
    public class AuthController : Controller
    {
        private readonly IConfiguration _config;
        private readonly IAuthService _authService;

        public AuthController(IConfiguration config, IAuthService authService)
        {
            _config = config;
            _authService = authService;
        }

        [HttpPost("token")]
        [Consumes("application/x-www-form-urlencoded")]
        public IActionResult GenerateToken([FromForm] string grant_type)
        {
            if (!Request.Headers.TryGetValue("Authorization", out var authHeader))
                return Unauthorized("Missing Authorization header");

            if (!authHeader.ToString().StartsWith("Basic "))
                return Unauthorized("Authorization must be Basic");

            var encodedCreds = authHeader.ToString().Substring("Basic ".Length).Trim();
            var decodedCreds = Encoding.UTF8.GetString(Convert.FromBase64String(encodedCreds));
            var parts = decodedCreds.Split(':');

            if (parts.Length != 2)
                return Unauthorized("Invalid basic auth format");

            var clientId = parts[0];
            var clientSecret = parts[1];

            if (clientId != _config["OAuth:client_id"] || clientSecret != _config["OAuth:client_secret"])
                return Unauthorized("Invalid client_id or client_secret");

            if (grant_type != "client_credentials")
                return BadRequest("Invalid grant_type");

            var token = _authService.GenerateAccessToken(clientId);
            
            return Ok(new
            {
                access_token = token,
                token_type = "bearer",
                expires_in = int.Parse(_config["OAuth:TokenExpiryInSeconds"]!)
            });
        }
    }
}
