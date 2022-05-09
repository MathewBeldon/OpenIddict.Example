using System.ComponentModel.DataAnnotations;

namespace OpenIddict.Example.IdP.Server.ViewModels.Account;

public sealed class ExternalLoginConfirmationViewModel
{
    [Required]
    [Display(Name = "Email")]
    public string Email { get; init; }

    [Required]
    [Display(Name = "First Name")]
    public string FirstName { get; init; }

    [Required]
    [Display(Name = "Last Name")]
    public string LastName { get; init; }
}
