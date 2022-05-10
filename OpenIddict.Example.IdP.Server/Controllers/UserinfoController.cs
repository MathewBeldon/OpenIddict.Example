using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Example.IdP.Persistence.Models;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddict.Example.IdP.Server.Controllers
{
    public class UserinfoController : Controller
    {
        private readonly UserManager<AppUser> _userManager;

        public UserinfoController(UserManager<AppUser> userManager)
            => _userManager = userManager;

        //
        // GET: /api/userinfo
        [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
        [HttpGet("~/connect/userinfo"), HttpPost("~/connect/userinfo"), Produces("application/json")]
        public async Task<IActionResult> Userinfo()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return Challenge(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidToken,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The specified access token is bound to an account that no longer exists."
                    }));
            }
            var claims = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [Claims.Subject] = user.Id
            };

            if (User.HasScope(Scopes.Profile))
            {
                claims[Claims.GivenName] = user.FirstName;
                claims[Claims.FamilyName] = user.LastName;
            }

            if (User.HasScope(Scopes.Email))
            {
                claims[Claims.Email] = user.Email;
                claims[Claims.EmailVerified] = user.EmailConfirmed;
            }

            if (User.HasScope(Scopes.Roles))
            {
                claims[Claims.Role] = await _userManager.GetRolesAsync(user);
            }

            return Ok(claims);
        }
    }
}
