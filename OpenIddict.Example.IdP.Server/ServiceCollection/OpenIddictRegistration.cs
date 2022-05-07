using Microsoft.IdentityModel.Tokens;
using OpenIddict.Example.IdP.Persistence;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddict.Example.IdP.Server.ServiceCollection
{
    internal static class OpenIddictRegistration
    {
        internal static IServiceCollection AddOpenIddictService(this IServiceCollection services, IConfiguration configuration)
        {
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

                    options
                        .AddEncryptionKey(new SymmetricSecurityKey(
                            Convert.FromBase64String(configuration.GetValue<string>("SymmetricSecurityKey"))));

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

            return services;
        }
    }
}
