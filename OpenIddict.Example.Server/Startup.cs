using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Example.IdP.Persistence;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Example.IdP.API
{
    public class Startup
    {
        public IConfiguration Configuration { get; }
        public Startup(IConfiguration configuration) => Configuration = configuration;
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();
            services.AddPersitenceServices(Configuration);
            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
                {
                    options.LoginPath = "/account/login";
                });

            services.AddOpenIddict()

                // Register the OpenIddict core components.
                .AddCore(options =>
                {
                    // Configure OpenIddict to use the EF Core stores/models.
                    options.UseEntityFrameworkCore()
                        .UseDbContext<DbContext>();
                })

                .AddServer(options =>
                {
                    // Enable the authorization, token, introspection and userinfo endpoints.
                    options.SetAuthorizationEndpointUris(Configuration["OpenIddict:Endpoints:Authorization"])
                           .SetTokenEndpointUris(Configuration["OpenIddict:Endpoints:Token"])
                           .SetIntrospectionEndpointUris(Configuration["OpenIddict:Endpoints:Introspection"])
                           .SetUserinfoEndpointUris(Configuration["OpenIddict:Endpoints:Userinfo"]);

                    // Enable the authorization code, implicit and the refresh token flows.
                    options.AllowAuthorizationCodeFlow()
                           .AllowImplicitFlow()
                           .AllowRefreshTokenFlow();

                    // Expose all the supported claims in the discovery document.
                    options.RegisterClaims(Configuration.GetSection("OpenIddict:Claims").Get<string[]>());

                    // Expose all the supported scopes in the discovery document.
                    options.RegisterScopes(Configuration.GetSection("OpenIddict:Scopes").Get<string[]>());

                    // Note: an ephemeral signing key is deliberately used to make the "OP-Rotation-OP-Sig"
                    // test easier to run as restarting the application is enough to rotate the keys.
                    options.AddEphemeralEncryptionKey()
                           .AddEphemeralSigningKey();

                    // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
                    //
                    // Note: the pass-through mode is not enabled for the token endpoint
                    // so that token requests are automatically handled by OpenIddict.
                    options.UseAspNetCore()
                           .EnableAuthorizationEndpointPassthrough()
                           .EnableAuthorizationRequestCaching();

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
