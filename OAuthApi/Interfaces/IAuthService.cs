namespace OAuthApi.Interfaces;

public interface IAuthService
{
    string GenerateAccessToken(string clientId);
}
