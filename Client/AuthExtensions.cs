using Microsoft.AspNetCore.Components.Authorization;

public static class AuthExtensions
{
    public static IServiceCollection AddStaticWebAppsAuthentication(this IServiceCollection services)
    {
        return services
            .AddAuthorizationCore()
            .AddScoped<AuthenticationStateProvider, StaticWebAppsAuthenticationStateProvider>();
    }
}