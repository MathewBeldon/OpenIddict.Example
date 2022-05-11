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

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
