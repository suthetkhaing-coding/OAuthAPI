using Microsoft.IdentityModel.Tokens;
using OAuthApi.Interfaces;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace OAuthApi.Services
{
    public class AuthService : IAuthService
    {
        private readonly IConfiguration _config;

        public AuthService(IConfiguration config)
        {
            _config = config;
        }

        public string GenerateAccessToken(string clientId)
        {
            var key = Encoding.UTF8.GetBytes(_config["OAuth:AccessTokenKey"]!);
            var creds = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);
            var expiry = DateTime.UtcNow.AddSeconds(int.Parse(_config["OAuth:TokenExpiryInSeconds"]!));

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("client_id", clientId),
                    new Claim("role", "OAuthClient")
                }),
                Expires = expiry,
                SigningCredentials = creds
            };

            var handler = new JwtSecurityTokenHandler();
            return handler.WriteToken(handler.CreateToken(tokenDescriptor));
        }
    }
}
