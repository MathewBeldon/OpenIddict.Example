using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Example.IdP.Persistence.Models;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddict.Example.IdP.Persistence
{
    public static class PersistenceServiceRegistration
    {
        public static void AddPersitenceServices(this IServiceCollection service, IConfiguration configuration)
        {
            var serverVersion = new MySqlServerVersion(configuration.GetConnectionString("MySQLVersion"));

            service.AddDbContext<AppDbContext>(options =>
            {
                options.UseMySql(configuration.GetConnectionString("MySQLConnectionString"), serverVersion);
                options.UseOpenIddict();
            });

            service.AddIdentity<AppUser, IdentityRole>()
                .AddEntityFrameworkStores<AppDbContext>()
                .AddDefaultTokenProviders()
                .AddDefaultUI();

            service.Configure<IdentityOptions>(options =>
            {
                options.ClaimsIdentity.UserNameClaimType = Claims.Name;
                options.ClaimsIdentity.UserIdClaimType = Claims.Subject;
                options.ClaimsIdentity.RoleClaimType = Claims.Role;
                options.ClaimsIdentity.EmailClaimType = Claims.Email;

                options.SignIn.RequireConfirmedAccount = false;
            });
        }
    }
}
