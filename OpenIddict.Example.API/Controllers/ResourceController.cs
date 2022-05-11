using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Validation.AspNetCore;

namespace OpenIddict.Example.API.Controllers
{
    [Route("api")]
    public sealed class ResourceController : Controller
    {
        [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
        [HttpGet("message")]
        public async Task<IActionResult> GetMessage()
        {
            return Content($"{User.Identity.Name} has been successfully authenticated.");
        }
    }
}
