using Microsoft.AspNetCore.Identity;

namespace OpenIddict.Example.IdP.Persistence.Models
{
    public sealed class AppUser : IdentityUser 
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
    }
}
