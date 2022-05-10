using System.ComponentModel.DataAnnotations;

namespace OpenIddict.Example.IdP.Server.ViewModels.Account
{
    public sealed class RegisterViewModel
    {
        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; init; }

        [Required]
        [Display(Name = "First Name")]
        public string FirstName { get; init; }

        [Required]
        [Display(Name = "Last Name")]
        public string LastName { get; init; }

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; init; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
        public string ConfirmPassword { get; init; }
    }
}
