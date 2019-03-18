using Dapper;
using JWTAuthentication.Abstract;
using JWTAuthentication.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Data.SqlClient;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;

namespace JWTAuthentication.Services
{
    public class AuthorizationService : IAuthorizationService
    {
        private IConfiguration config;

        public AuthorizationService(IConfiguration config)
        {
            this.config = config;
        }

        public string GenerateJSONWebToken(UserModel user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[] {
                new Claim(JwtRegisteredClaimNames.GivenName, user.FullName),
                new Claim(JwtRegisteredClaimNames.Email, user.EmailAddress),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(
                config["Jwt:Issuer"],
                config["Jwt:Issuer"],
                expires: DateTime.Now.AddMinutes(120),
                signingCredentials: credentials,
                claims: claims);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public UserModel AuthenticateUser(UserModel userLogin)
        {
            if (!CheckIfTheUserExists(userLogin.EmailAddress))
                return null;

            var user = GetUser(userLogin.EmailAddress);

            if (user != null)
            {
                if (!VerifyPasswordHash(userLogin.Password, user.PasswordHash, user.Salt))
                    return null;
            }

            return user;
        }

        public bool RegisterUser(UserModel user)
        {
            if (CheckIfTheUserExists(user.EmailAddress))
                return false;

            byte[] passwordHash;
            byte[] passwordSalt;

            CreatePasswordHash(user.Password, out passwordHash, out passwordSalt);

            user.PasswordHash = passwordHash;
            user.Salt = passwordSalt;

            using (var connection = new SqlConnection(config["Db:ConnectionString"]))
            {
                var command = $"INSERT INTO [dbo].[User] ([Id], [EmailAddress], [FullName], [PasswordHash], [Salt]) " +
                    $"VALUES (@Id, @EmailAddress, @FullName, @Password, @Salt)";

                var Id = Guid.NewGuid();
                var EmailAddress = user.EmailAddress;
                var FullName = user.FullName;
                var Password = user.PasswordHash;
                var Salt = user.Salt;

                connection.Execute(command, new
                {
                    Id,
                    EmailAddress,
                    FullName,
                    Password,
                    Salt
                });
            }

            return true;
        }

        private UserModel GetUser(string email)
        {
            using (var connection = new SqlConnection(config["Db:ConnectionString"]))
            {
                var sqlQuery = $"SELECT [FullName], [EmailAddress], [PasswordHash], [Salt] " +
                    $"FROM [dbo].[User] " +
                    $"WHERE [EmailAddress] = '{email}'";

                var user = connection.Query<UserModel>(sqlQuery).FirstOrDefault();

                if (user == null)
                    return null;

                return user;
            }
        }

        private bool CheckIfTheUserExists(string email)
        {
            using (var connection = new SqlConnection(config["Db:ConnectionString"]))
            {
                var sqlQuery = $"SELECT [Id] " +
                    $"FROM [dbo].[User] " +
                    $"WHERE [EmailAddress] = '{email}'";

                var userId = connection.Query<string>(sqlQuery).FirstOrDefault();

                if (userId == null)
                    return false;
            }

            return true;
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new System.Security.Cryptography.HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] storedHash, byte[] storedSalt)
        {
            using (var hmac = new System.Security.Cryptography.HMACSHA512(storedSalt))
            {
                var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));

                for (int i = 0; i < computedHash.Length; i++)
                {
                    if (computedHash[i] != storedHash[i])
                        return false;
                }
            }

            return true;
        }
    }
}
