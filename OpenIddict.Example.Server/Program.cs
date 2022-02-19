namespace OpenIddict.Example.Server
{
    public sealed class Program
    {
        public static Task Main(string[] args) =>
            CreateHost(args).RunAsync();


        public static IHost CreateHost(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureAppConfiguration((env, config) =>
                {
                    config.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);
                    config.AddJsonFile($"appsettings.{env.HostingEnvironment.EnvironmentName}.json", optional: true, reloadOnChange: true);
                })
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                }).Build();
    }
}
