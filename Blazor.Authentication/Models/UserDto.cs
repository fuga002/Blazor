namespace Blazor.Authentication.Models;

public class UserDto
{
    public Guid Id { get; set; }
    public string Firstname { get; set; }
    public string Lastname { get; set; }
    public string Username { get; set; }
    public DateTime CreatedAt { get; set; }
    public string? PhotoUrl { get; set; }

    /*
    public List<BlogDto>? Blogs { get; set; }*/
}