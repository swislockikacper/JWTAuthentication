using JWTAuthentication.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JWTAuthentication.Controllers
{
    [ApiController]
    public class LoginController : Controller
    {
        private readonly Abstract.IAuthorizationService userService;

        public LoginController(Abstract.IAuthorizationService userService)
        {
            this.userService = userService;
        }

        [Route("api/Login")]
        [AllowAnonymous]
        [HttpPost]
        public IActionResult Login([FromBody]UserModel loginUser)
        {
            var user = userService.AuthenticateUser(loginUser);

            if (user != null)
                return Ok(new { token = userService.GenerateJSONWebToken(user) });

            return Unauthorized();
        }

        [Route("api/Register")]
        [AllowAnonymous]
        [HttpPost]
        public IActionResult Register([FromBody]UserModel user)
        {
            if (userService.RegisterUser(user))
                return Ok();

            return BadRequest("User exists!");
        }
    }
}
