using System.ComponentModel.DataAnnotations;

namespace OpenIddict.Example.IdP.API.ViewModels
{
    public sealed class LoginViewModel
    {
        [Required]
        public string Username { get; set; }
        [Required]
        public string Password { get; set; }
        public string? ReturnUrl { get; set; }
    }
}
