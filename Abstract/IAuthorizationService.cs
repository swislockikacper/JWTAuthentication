using JWTAuthentication.Models;

namespace JWTAuthentication.Abstract
{
    public interface IAuthorizationService
    {
        string GenerateJSONWebToken(UserModel userInfo);
        UserModel AuthenticateUser(UserModel login);
        bool RegisterUser(UserModel user);
    }
}
