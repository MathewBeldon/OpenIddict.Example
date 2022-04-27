using System.ComponentModel.DataAnnotations;

namespace OpenIddict.Sandbox.AspNetCore.Server.ViewModels.Account;

public sealed class ExternalLoginConfirmationViewModel
{
    [Required]
    [EmailAddress]
    public string Email { get; set; }
}
