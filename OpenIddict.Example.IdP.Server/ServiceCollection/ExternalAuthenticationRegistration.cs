namespace OpenIddict.Example.IdP.Server.ServiceCollection
{
    internal static class ExternalAuthenticationRegistration
    {
        internal static IServiceCollection AddExternalAuthenticationService(this IServiceCollection services, IConfiguration configuration)
        {
            var github = configuration.GetSection("Authentication:GitHub");
            if (github.Exists())
            {
                services
                    .AddAuthentication()
                    .AddGitHub(options =>
                    {
                        options.ClientId = github["ClientId"];
                        options.ClientSecret = github["ClientSecret"];
                    });
            }

            var okta = configuration.GetSection("Authentication:Okta");
            if (okta.Exists())
            {
                services
                    .AddAuthentication()
                    .AddOkta(options =>
                    {
                        options.ClientId = okta["ClientId"];
                        options.ClientSecret = okta["ClientSecret"];
                        options.Domain = okta["Domain"];
                    });
            }
            
            return services;
        }
    }
}
