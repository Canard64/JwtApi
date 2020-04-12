using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using WebApplication1.Model;

namespace WebApplication1.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private IConfiguration _config;

        public LoginController(IConfiguration config)
        {
            _config = config;
        }

        [HttpGet]
        public IActionResult Login(String username, String pwd)
        {
            UserModel login = new UserModel();
            login.UserName = username;
            login.Password = pwd;

            IActionResult response = Unauthorized();
            var user = AuthenticateUser(login);

            if (user !=null)
            {
                var tokenStr = GenerateJSONWenToken(user);
                response = Ok(new { token = tokenStr });

            }
            return response;
        }

        [Authorize]
        [HttpPost("Post")]
        public string Post()
        {
            var identity = HttpContext.User.Identity as ClaimsIdentity;
            IList<Claim> claim = identity.Claims.ToList();
            var userName = claim[0].Value;

            return "Welcome " + userName;
        }

        [Authorize]
        [HttpGet("GetValue")]
        ActionResult<IEnumerable<string>> Get()
        {
            return new string[] { "Value1", "Value2", "Value3" };
        }

        private UserModel AuthenticateUser(UserModel login)
        {
            UserModel user = null;

            if (login.UserName=="toto" && login.Password=="toto")
            {
                user = new UserModel { UserName = "COUCOU", Email = "ttppt@gmail.com", Password="toto" };
            }
            return user;
        }

        private string GenerateJSONWenToken(UserModel userInfo)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credential = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub,userInfo.UserName),
                new Claim(JwtRegisteredClaimNames.Email,userInfo.Email),
                new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),


            };

            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Issuer"],
                claims,
                expires: DateTime.Now.AddMinutes(120),
                signingCredentials: credential) ;

            var encodedToken = new JwtSecurityTokenHandler().WriteToken(token);

            return encodedToken;

        }
    }
}