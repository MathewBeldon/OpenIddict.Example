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

            services.AddAuthentication()
                .AddGitHub(options =>
                {
                    options.ClientId = "";
                    options.ClientSecret = "";
                });

            services.AddOpenIddict()

                // Register the OpenIddict core components.
                .AddCore(options =>
                {
                    // Configure OpenIddict to use the EF Core stores/models.
                    options.UseEntityFrameworkCore()
                        .UseDbContext<AppDbContext>();
                })

                .AddServer(options =>
                {
                    // Enable the authorization, device, introspection,
                    // logout, token, userinfo and verification endpoints.
                    options.SetAuthorizationEndpointUris("/connect/authorize")
                           .SetDeviceEndpointUris("/connect/device")
                           .SetIntrospectionEndpointUris("/connect/introspect")
                           .SetLogoutEndpointUris("/connect/logout")
                           .SetTokenEndpointUris("/connect/token")
                           .SetUserinfoEndpointUris("/connect/userinfo")
                           .SetVerificationEndpointUris("/connect/verify");

                    // Note: this sample uses the code, device code, password and refresh token flows, but you
                    // can enable the other flows if you need to support implicit or client credentials.
                    options.AllowAuthorizationCodeFlow()
                           .AllowDeviceCodeFlow()
                           .AllowPasswordFlow()
                           .AllowRefreshTokenFlow();

                    options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles, "demo_api");

                    options.AddDevelopmentEncryptionCertificate()
                           .AddDevelopmentSigningCertificate();

                    options.RequireProofKeyForCodeExchange();

                    options.UseAspNetCore()
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
                    // Import the configuration from the local OpenIddict server instance.
                    options.UseLocalServer();
                    // Register the ASP.NET Core host.
                    options.UseAspNetCore();

                    // Enable authorization entry validation, which is required to be able
                    // to reject access tokens retrieved from a revoked authorization code.
                    options.EnableAuthorizationEntryValidation();
                });

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
