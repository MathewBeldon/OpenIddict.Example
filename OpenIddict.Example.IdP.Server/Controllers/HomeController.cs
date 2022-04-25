using Microsoft.AspNetCore.Mvc;

namespace OpenIddict.Example.IdP.Server.Controllers
{
    public sealed class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
