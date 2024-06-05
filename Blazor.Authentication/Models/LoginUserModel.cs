using System.ComponentModel.DataAnnotations;

namespace Blazor.Authentication.Models;

public class LoginUserModel
{
    [Required]
    public string UserName { get; set; }
    [Required]
    public string Password { get; set; }
}