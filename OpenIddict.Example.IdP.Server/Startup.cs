using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Example.IdP.Persistence;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddict.Example.IdP.Server
{
    public class Startup
    {
        public IConfiguration Configuration { get; }
        public Startup(IConfiguration configuration) => Configuration = configuration;
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();
            services.AddPersitenceServices(Configuration);

            //services.AddAuthentication()
            //    .AddGitHub(options =>
            //    {
            //        options.ClientId = "";
            //        options.ClientSecret = "";
            //    });

            //services.AddAuthentication()
            //    .AddOkta(options =>
            //    {
            //        options.ClientId = "";
            //        options.ClientSecret = "";
            //    });

            services
                .AddOpenIddict()

                .AddCore(options =>
                {
                    options
                        .UseEntityFrameworkCore()
                        .UseDbContext<AppDbContext>();
                })

                .AddServer(options =>
                {
                    options
                        .SetAuthorizationEndpointUris("/connect/authorize")
                        .SetDeviceEndpointUris("/connect/device")
                        .SetIntrospectionEndpointUris("/connect/introspect")
                        .SetLogoutEndpointUris("/connect/logout")
                        .SetTokenEndpointUris("/connect/token")
                        .SetUserinfoEndpointUris("/connect/userinfo")
                        .SetVerificationEndpointUris("/connect/verify");

                    options
                        .AllowAuthorizationCodeFlow()
                        .AllowDeviceCodeFlow()
                        .AllowPasswordFlow()
                        .AllowRefreshTokenFlow();

                    options.AddEncryptionKey(new SymmetricSecurityKey(
                        Convert.FromBase64String("DRjd/GnduI3Efzen9V9BvbNUfc/VKgXltV7Kbk9sMkY=")));

                    options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles, "openiddict_resource");

                    options
                        .AddDevelopmentEncryptionCertificate()
                        .AddDevelopmentSigningCertificate();

                    options.RequireProofKeyForCodeExchange();

                    options
                        .UseAspNetCore()
                        .EnableStatusCodePagesIntegration()
                        .EnableAuthorizationEndpointPassthrough()
                        .EnableLogoutEndpointPassthrough()
                        .EnableTokenEndpointPassthrough()
                        .EnableUserinfoEndpointPassthrough()
                        .EnableVerificationEndpointPassthrough()
                        .DisableTransportSecurityRequirement();


                })

                .AddValidation(options =>
                {
                    options.UseLocalServer();
                    options.UseAspNetCore();

                    options.EnableAuthorizationEntryValidation();
                });

            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme);
            services.AddHostedService<Worker>();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseStaticFiles();

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
            });
        }
    }
}
