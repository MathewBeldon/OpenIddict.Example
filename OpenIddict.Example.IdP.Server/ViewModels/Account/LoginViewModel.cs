using System.ComponentModel.DataAnnotations;

namespace OpenIddict.Example.IdP.Server.ViewModels.Account
{
    public sealed class LoginViewModel
    {
        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; init; }

        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; init; }

        [Display(Name = "Remember me?")]
        public bool RememberMe { get; init; }
    }
}
