using Microsoft.AspNetCore.Mvc;

namespace OpenIddict.Example.IdP.Controllers
{
    public sealed class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
