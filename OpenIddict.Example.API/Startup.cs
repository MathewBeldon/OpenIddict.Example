using Microsoft.IdentityModel.Tokens;
using OpenIddict.Example.API.ServiceCollection;
using OpenIddict.Validation.AspNetCore;

namespace OpenIddict.Example.API
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
            services.AddSwaggerService();
            services.AddControllers();

            services.AddOpenIddict()
                .AddValidation(options =>
                {
                    options.SetIssuer("https://localhost:7213/");
                    options.AddAudiences("resource_server_api");

                    options
                        .AddEncryptionKey(new SymmetricSecurityKey(
                            Convert.FromBase64String(Configuration.GetValue<string>("SymmetricSecurityKey"))));
                    var x = Configuration.GetValue<string>("SymmetricSecurityKey");
                    
                    options.UseSystemNetHttp();

                    options.UseAspNetCore();
                });

            services.AddRouting(options => {
                options.LowercaseUrls = true;
            });

            services.AddCors(options =>
            {
                options.AddPolicy("Open", builder => builder.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod());
            });

            services.AddAuthentication(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
            services.AddAuthorization();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseSwagger();
                app.UseSwaggerUI(o =>
                {
                    o.DisplayRequestDuration();
                    o.SwaggerEndpoint("/swagger/v1/swagger.json", "OpenIddict Example API");
                });
            }

            app.UseHttpsRedirection();
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseCors("Open");

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
