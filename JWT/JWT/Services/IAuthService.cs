using JWT.Models;
using System.IdentityModel.Tokens.Jwt;

namespace JWT.Services
{
    public interface IAuthService
    {
        Task<AuthModel>RegisterAsync(RegisterModel model);
       
        Task<AuthModel> GetTokenAsync(TokenRequestModel model);

        Task<string> AddRoleAsync(AddRoleModel model);
    }
}
