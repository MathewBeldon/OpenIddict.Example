using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace OpenIddict.Example.Client
{
    public sealed class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })

            .AddCookie(options =>
            {
                options.LoginPath = "/login";
                options.ExpireTimeSpan = TimeSpan.FromMinutes(50);
                options.SlidingExpiration = false;
            })

            .AddOpenIdConnect(options =>
            {
                // Note: these settings must match the application details
                // inserted in the database at the server level.
                options.ClientId = "openiddict_example_client";
                //options.ClientSecret = "postman-secret";

                options.RequireHttpsMetadata = false;
                options.GetClaimsFromUserInfoEndpoint = true;
                options.SaveTokens = true;

                // Use the authorization code flow.
                options.ResponseType = OpenIdConnectResponseType.Code;
                options.AuthenticationMethod = OpenIdConnectRedirectBehavior.RedirectGet;

                // Note: setting the Authority allows the OIDC client middleware to automatically
                // retrieve the identity provider's configuration and spare you from setting
                // the different endpoints URIs or the token validation parameters explicitly.
                options.Authority = "https://localhost:7213/";

                options.Scope.Add("openid");
                options.Scope.Add("openiddict_example_resource");
                options.Scope.Add("profile");

                // Disable the built-in JWT claims mapping feature.
                options.MapInboundClaims = false;

                options.TokenValidationParameters.NameClaimType = "name";
                options.TokenValidationParameters.RoleClaimType = "role";
            });

            services.AddControllersWithViews();

            services.AddHttpClient();
        }

        public void Configure(IApplicationBuilder app)
        {
            app.UseDeveloperExceptionPage();

            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(options =>
            {
                options.MapControllers();
                options.MapDefaultControllerRoute();
            });
        }
    }
}
