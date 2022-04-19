using OpenIddict.Example.API.ServiceCollection;

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
            //services.AddScoped<ILoggedInUserService, LoggedInUserService>();
            //services.AddApiVersioningService();

            services.AddRouting(options => {
                options.LowercaseUrls = true;
            });

            services.AddCors(options =>
            {
                options.AddPolicy("Open", builder => builder.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod());
            });
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

            //app.UseSerilogRequestLogging();

            app.UseHttpsRedirection();
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseCors("Open");

            //app.UseCustomExceptionHandler();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
