using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace BlazorApp1.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        IConfiguration Configuration;
        TokenValidationParameters _tokenvalidationParameters;
        public AuthController(IConfiguration Config)
        {
            this.Configuration = Config;
        }

        [HttpGet("login")]
        public IActionResult Login(string user, string pass)
        {
            string tokenstring = GenerateToken(user, pass);
            return Ok(tokenstring);
        }
        private string GenerateToken(string user, string pass, string secret = "")
        {
            Claim[] claims = null;
            string tokenAsString = "";

            if ((user == "usuario" && pass == "usuario") || (user == "usuario" && secret == Configuration["AuthSettings:key"]))
            {
                claims = new[]
                {
                    new Claim("Email","usuario@usuario.com"),
                    //new Claim(ClaimTypes.NameIdentifier,"2577"), TokensJWT
                    new Claim(JwtRegisteredClaimNames.UniqueName,"Rik"),
                    new Claim("User","usuario"),
                    new Claim("Rol","Usuario"),
                    new Claim(ClaimTypes.Role,"Usuario")
                };
                IdentityModelEventSource.ShowPII = true;
                var keybuffer = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["AuthSettings:key"]));
                DateTime expireTime = DateTime.Now.AddSeconds(30);
                var token = new JwtSecurityToken(issuer: Configuration["AuthSettings:Issuer"], audience: Configuration["AuthSettings:Audince"], claims, expires: expireTime, signingCredentials: new SigningCredentials(keybuffer, SecurityAlgorithms.HmacSha256));

                tokenAsString = new JwtSecurityTokenHandler().WriteToken(token);


            }

            return tokenAsString;
        }
        [HttpGet("Refresh")]
        public IActionResult Refresh(string token, string secret)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            string newToken = "";
            try
            {
                newToken = "";
                // se valida el token principal
                _tokenvalidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidAudience = Configuration["AuthSettings:Audince"],// valida de donde viene el token y si es corrento lo usa 
                    ValidIssuer = Configuration["AuthSettings:Issuer"],
                    RequireExpirationTime = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["AuthSettings:key"])),

                };
                var pricipal = tokenHandler.ValidateToken(token, _tokenvalidationParameters, out var validatedToken);
                if (!IsJwtWithValidSecurityAlgoritm(validatedToken))
                {
                    return null;
                }
                // usar clases especificas
                var expiryDate = long.Parse(pricipal.Claims.Single(o => o.Type == JwtRegisteredClaimNames.Exp).Value);
                var DateTimeExpire = new DateTime(expiryDate);
                var exp = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(expiryDate);//.Subtract(_tokenvalidationParameters.);
                if (exp > DateTime.UtcNow)
                {
                    //aun no expira
                }
                else
                {
                    // expiro , volver a generarlo 
                    var user = pricipal.Claims.Single(o => o.Type == "User").Value;
                    newToken = GenerateToken(user, "", secret);
                }


            }
            catch (Exception e)
            {

            }
            return Ok(newToken);
        }
        private bool IsJwtWithValidSecurityAlgoritm(SecurityToken token)
        {
            return (token is JwtSecurityToken jwtSecurotyToken) && jwtSecurotyToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCulture);
        }
    }
}
