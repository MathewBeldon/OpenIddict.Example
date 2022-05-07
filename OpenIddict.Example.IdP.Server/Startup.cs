using Microsoft.AspNetCore.Authentication.Cookies;
using OpenIddict.Example.IdP.Persistence;
using OpenIddict.Example.IdP.Server.ServiceCollection;

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

            services.AddExternalAuthenticationService(Configuration);

            services.AddOpenIddictService(Configuration);

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
