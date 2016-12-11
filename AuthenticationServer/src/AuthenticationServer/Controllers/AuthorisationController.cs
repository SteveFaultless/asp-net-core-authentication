using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AuthenticationServer.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
//using OpenIddict;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Authentication;
using Newtonsoft.Json;
using Newtonsoft.Json.Bson;

namespace AuthenticationServer.Controllers
{
    public class AuthorisationController : Controller
    {
        //private readonly OpenIddictApplicationManager<OpenIddictApplication> _applicationManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;

        public AuthorisationController(
           // OpenIddictApplicationManager<OpenIddictApplication> applicationManager,
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager)
        {
           // _applicationManager = applicationManager;
            _signInManager = signInManager;
            _userManager = userManager;
        }

        [HttpPost, Produces("application/json")]
        public async Task<IActionResult> Authorise()
        {
            try
            {
                using (BsonReader reader = new BsonReader(HttpContext.Request.Body))
                {
                    JsonSerializer serializer = new JsonSerializer();
                    LoginDatum datum = serializer.Deserialize<LoginDatum>(reader);
                    return await AuthoriseJson(datum);
                }

            }
            catch (Exception ex)
            {
                Console.Out.WriteLine(ex);
            }
            return BadRequest(new OpenIdConnectResponse
            {
                Error = OpenIdConnectConstants.Errors.UnsupportedGrantType,
                //ErrorDescription = login.ToString()
            });
        }
        /// <summary>
        /// result = {
        ///     ResultCode=1, 
	    ///     UserId=request.query['username'], 
	    ///     AuthCookie={IsAdmin=true}
        /// } 
        /// return json.stringify(result)
        /// </summary>
        /// <param name="datum"></param>
        /// <returns></returns>
        [HttpPost, Produces("application/json")]
        public async Task<IActionResult> AuthoriseJson([FromBody]LoginDatum datum)
        {
            Microsoft.AspNetCore.Identity.SignInResult result =
                await
                    _signInManager.PasswordSignInAsync(datum.Username, datum.Password, isPersistent: true,
                        lockoutOnFailure: false);
            if (result.Succeeded)
            {

                return new JsonResult(new {UserName = datum.Username, ResultCode = 1, AuthCookie = new {IsAdmin = true}});
            }
            else
            {
                return new JsonResult(new {ResultCode = 2});
            }

        }

        public class LoginDatum
        {
            public string Username { get; set; }
            public string Password { get; set; }
        }

        public class SuccessfulLogin
        {
            public string UserId { get; set; }
            public int ResultCode { get; set; }
            public string AuthCookie { get; set; }
        }
    }
}