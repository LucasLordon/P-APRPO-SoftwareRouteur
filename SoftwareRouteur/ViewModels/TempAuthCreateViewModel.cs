using System.ComponentModel.DataAnnotations;
using SoftwareRouteur.Models;

namespace SoftwareRouteur.ViewModels;

public class TempAuthCreateViewModel
{
    [Required]
    public int ProfileId { get; set; }

    public int? ClientId { get; set; }

    [Required]
    [Range(1, 1440)]
    public int DurationMinutes { get; set; } = 30;

    public string? AllowDestination { get; set; }
    public string? AllowDestinationType { get; set; }

    public List<Profile> AvailableProfiles { get; set; } = new();
    public List<Client> AvailableClients { get; set; } = new();
}
