using OpenIddict.Abstractions;
using OpenIddict.Example.IdP.Persistence;
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

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            await using var serviceScope = _serviceProvider.CreateAsyncScope();

            var context = serviceScope.ServiceProvider.GetRequiredService<AppDbContext>();
            await context.Database.EnsureCreatedAsync();

            var appManager = serviceScope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            
            var appDescriptors = _configuration.GetSection("OpenIddict:Clients").Get<OpenIddictApplicationDescriptor[]>();
            if (appDescriptors.Length == 0)
            {
                throw new InvalidOperationException("No client application was found in the configuration file.");
            }

            foreach (var client in appDescriptors)
            {
                if (await appManager.FindByClientIdAsync(client.ClientId!) is null)
                {
                    await appManager.CreateAsync(client);
                }                
            }

            var scopeManager = serviceScope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
            var scopeDescriptors = _configuration.GetSection("OpenIddict:Scopes").Get<OpenIddictScopeDescriptor[]>();
            if (scopeDescriptors.Length == 0)
            {
                throw new InvalidOperationException("No scopes found in the configuration file.");
            }

            foreach (var scope in scopeDescriptors)
            {
                if (await scopeManager.FindByNameAsync(scope.Name!) is null)
                {
                    await scopeManager.CreateAsync(scope);
                }                
            }
        }

        //public async Task StartAsync(CancellationToken cancellationToken)
        //{
        //    using var scope = _serviceProvider.CreateScope();

        //    var context = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        //    await context.Database.EnsureCreatedAsync(cancellationToken);

        //    await RegisterApplicationsAsync(scope.ServiceProvider);
        //    await RegisterScopesAsync(scope.ServiceProvider);

        //    static async Task RegisterApplicationsAsync(IServiceProvider provider)
        //    {
        //        var manager = provider.GetRequiredService<IOpenIddictApplicationManager>();

        //        Blazor Hosted
        //        if (await manager.FindByClientIdAsync("postman2") is null)
        //        {
        //            await manager.CreateAsync(new OpenIddictApplicationDescriptor
        //            {
        //                ClientId = "postman2",
        //                ConsentType = ConsentTypes.Explicit,
        //                DisplayName = "PKCE",
        //                PostLogoutRedirectUris =
        //                {
        //                    new Uri("https://localhost:7060/signout-callback-oidc")
        //                },
        //                RedirectUris =
        //                {
        //                    new Uri("https://localhost:7060/signin-oidc")
        //                },
        //                Permissions =
        //                {
        //                    Permissions.Endpoints.Authorization,
        //                    Permissions.Endpoints.Logout,
        //                    Permissions.Endpoints.Token,
        //                    Permissions.GrantTypes.AuthorizationCode,
        //                    Permissions.ResponseTypes.Code,
        //                    Permissions.Scopes.Email,
        //                    Permissions.Scopes.Profile,
        //                    Permissions.Scopes.Roles,
        //                    Permissions.Prefixes.Scope + "openiddict_resource"
        //                },
        //                Requirements =
        //                {
        //                    Requirements.Features.ProofKeyForCodeExchange
        //                }
        //            });
        //        }

        //        if (await manager.FindByClientIdAsync("postman4") is null)
        //        {
        //            await manager.CreateAsync(new OpenIddictApplicationDescriptor
        //            {
        //                ClientId = "postman4",
        //                ConsentType = ConsentTypes.Explicit,
        //                DisplayName = "PKCE2",
        //                PostLogoutRedirectUris =
        //                {
        //                    new Uri("https://localhost:44339/signout-callback-oidc")
        //                },
        //                RedirectUris =
        //                {
        //                    new Uri("https://localhost:44339/signin-oidc")
        //                },
        //                Permissions =
        //                {
        //                    Permissions.Endpoints.Authorization,
        //                    Permissions.Endpoints.Logout,
        //                    Permissions.Endpoints.Token,
        //                    Permissions.GrantTypes.AuthorizationCode,
        //                    Permissions.ResponseTypes.Code,
        //                    Permissions.Scopes.Email,
        //                    Permissions.Scopes.Profile,
        //                    Permissions.Scopes.Roles,
        //                    Permissions.Prefixes.Scope + "openiddict_resource"
        //                },
        //                Requirements =
        //                {
        //                    Requirements.Features.ProofKeyForCodeExchange
        //                }
        //            });
        //        }
        //    }

        //    static async Task RegisterScopesAsync(IServiceProvider provider)
        //    {
        //        var manager = provider.GetRequiredService<IOpenIddictScopeManager>();

        //        if (await manager.FindByNameAsync("openiddict_resource") is null)
        //        {
        //            await manager.CreateAsync(new OpenIddictScopeDescriptor
        //            {
        //                DisplayName = "OpenIddict Example",
        //                Name = "openiddict_resource",
        //                Resources =
        //                {
        //                    "resource_server_api"
        //                }
        //            });
        //        }
        //    }
        //}

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
