using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components.Authorization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Blazor.Authentication.Services;

public class CustomAuthenticationStateProvider:AuthenticationStateProvider
{
    private readonly ILocalStorageService _localStorageService;

    public CustomAuthenticationStateProvider(ILocalStorageService localStorageService)
    {
        _localStorageService = localStorageService;
    }

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        var claimsPrincipal = await SetClaims();

        return await Task.FromResult(new AuthenticationState(claimsPrincipal));
    }

    private async Task<ClaimsPrincipal> SetClaims()
    {
        var (username, userId, check) = await ReadJwtToken();

        if (!check)
        {
            return new ClaimsPrincipal();
        }

        var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>()
        {
            new Claim(ClaimTypes.NameIdentifier,userId),
            new Claim(ClaimTypes.Name,username)
        }, "JwtAuth"));
        return claimsPrincipal;
    }

    public async Task UpdateState()
    {
        var claimsPrincipal = await SetClaims();
        NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(claimsPrincipal)));
    }

    private async Task<Tuple<string, string, bool>> ReadJwtToken()
    {
        var token = await _localStorageService.GetItemAsync<string>("jwt-token");

        if (token == null)
            return new(null,null,false);

        var security = new JwtSecurityTokenHandler();

        var readToken = security.ReadJwtToken(token);

        var username = readToken.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)!.Value;
        var userId = readToken.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)!.Value;

        return new(username,userId,true);
    }



}