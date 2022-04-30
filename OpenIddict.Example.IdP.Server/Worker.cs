using OpenIddict.Abstractions;
using OpenIddict.Example.IdP.Persistence;
using System.Globalization;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddict.Example.IdP.Server
{
    public class Worker : IHostedService
    {
        private readonly IConfiguration _configuration;
        private readonly IServiceProvider _serviceProvider;

        public Worker(
            IConfiguration configuration,
            IServiceProvider serviceProvider)
        {
            _configuration = configuration;
            _serviceProvider = serviceProvider;
        }

        //public async Task StartAsync(CancellationToken cancellationToken)
        //{
        //    await using var scope = _serviceProvider.CreateAsyncScope();

        //    var context = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        //    await context.Database.EnsureCreatedAsync();

        //    var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        //    // Retrieve the client definitions from the configuration
        //    // and insert them in the applications table if necessary.
        //    var descriptors = _configuration.GetSection("OpenIddict:Clients").Get<OpenIddictApplicationDescriptor[]>();
        //    if (descriptors.Length == 0)
        //    {
        //        throw new InvalidOperationException("No client application was found in the configuration file.");
        //    }

        //    foreach (var descriptor in descriptors)
        //    {
        //        if (await manager.FindByClientIdAsync(descriptor.ClientId!) is not null)
        //        {
        //            continue;
        //        }

        //        await manager.CreateAsync(descriptor);
        //    }
        //}

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            using var scope = _serviceProvider.CreateScope();

            var context = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            await context.Database.EnsureCreatedAsync(cancellationToken);

            await RegisterApplicationsAsync(scope.ServiceProvider);
            await RegisterScopesAsync(scope.ServiceProvider);

            static async Task RegisterApplicationsAsync(IServiceProvider provider)
            {
                var manager = provider.GetRequiredService<IOpenIddictApplicationManager>();

                // Blazor Hosted
                if (await manager.FindByClientIdAsync("postman") is null)
                {
                    await manager.CreateAsync(new OpenIddictApplicationDescriptor
                    {
                        ClientId = "postman",
                        ConsentType = ConsentTypes.Explicit,
                        DisplayName = "PKCE",
                        PostLogoutRedirectUris =
                        {
                            new Uri("https://localhost:7060/signout-callback-oidc")
                        },
                        RedirectUris =
                        {
                            new Uri("https://localhost:7060/signin-oidc")
                        },
                        ClientSecret = "postman-secret",
                        Permissions =
                        {
                            Permissions.Endpoints.Authorization,
                            Permissions.Endpoints.Logout,
                            Permissions.Endpoints.Token,
                            Permissions.GrantTypes.AuthorizationCode,
                            Permissions.ResponseTypes.Code,
                            Permissions.Scopes.Email,
                            Permissions.Scopes.Profile,
                            Permissions.Scopes.Roles,
                            Permissions.Prefixes.Scope + "openiddict_resource"
                        },
                        Requirements =
                        {
                            Requirements.Features.ProofKeyForCodeExchange
                        }
                    });
                }
            }

            static async Task RegisterScopesAsync(IServiceProvider provider)
            {
                var manager = provider.GetRequiredService<IOpenIddictScopeManager>();

                if (await manager.FindByNameAsync("openiddict_resource") is null)
                {
                    await manager.CreateAsync(new OpenIddictScopeDescriptor
                    {
                        DisplayName = "OpenIddict Example",
                        Name = "openiddict_resource",
                        Resources =
                        {
                            "resource_server_api"
                        }
                    });
                }
            }
        }

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
