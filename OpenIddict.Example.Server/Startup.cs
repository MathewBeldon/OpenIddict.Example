using Microsoft.EntityFrameworkCore;
using OpenIddict.Example.Server.Persistance;

namespace OpenIddict.Example.Server
{
    public sealed class Startup
    {
        public IConfiguration Configuration { get; }
        public IWebHostEnvironment Environment { get; }
        public Startup(IConfiguration configuration, IWebHostEnvironment environment)
        {
            Configuration = configuration;
            Environment = environment;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();

            services.AddDbContext<ApplicationDbContext>(options =>
            {
                // Configure Entity Framework Core to use Microsoft SQL Server.
                options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection"));

                // Register the entity sets needed by OpenIddict.
                // Note: use the generic overload if you need to replace the default OpenIddict entities.
                options.UseOpenIddict();
            });

            services.AddOpenIddict()

                // Register the OpenIddict core components.
                .AddCore(options =>
                {
            // Configure OpenIddict to use the Entity Framework Core stores and models.
            // Note: call ReplaceDefaultEntities() to replace the default entities.
            options.UseEntityFrameworkCore()
                           .UseDbContext<ApplicationDbContext>();
                })
                // Register the OpenIddict server components.
                .AddServer(options =>
                {
                // Enable the token endpoint.
                options.SetTokenEndpointUris("/connect/token");

                // Enable the client credentials flow.
                options.AllowClientCredentialsFlow();

                // Register the signing and encryption credentials.
                options.AddDevelopmentEncryptionCertificate()
                               .AddDevelopmentSigningCertificate();

                // Register the ASP.NET Core host and configure the ASP.NET Core options.
                options.UseAspNetCore()
                               .EnableTokenEndpointPassthrough();
                    })

                    // Register the OpenIddict validation components.
                    .AddValidation(options =>
                    {
                // Import the configuration from the local OpenIddict server instance.
                options.UseLocalServer();

                // Register the ASP.NET Core host.
                options.UseAspNetCore();
                });


            services.AddEndpointsApiExplorer();
            services.AddSwaggerGen();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {            
            if (env.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
                endpoints.MapDefaultControllerRoute();
            });
        }
    }
}
