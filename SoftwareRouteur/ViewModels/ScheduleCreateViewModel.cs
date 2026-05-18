using System.ComponentModel.DataAnnotations;
using SoftwareRouteur.Models;

namespace SoftwareRouteur.ViewModels;

public class ScheduleCreateViewModel
{
    public int? ProfileId { get; set; }
    public int? ClientId { get; set; }

    [Required]
    public string TimeStart { get; set; } = "";

    [Required]
    public string TimeEnd { get; set; } = "";

    [Required]
    public string Days { get; set; } = "0000000";

    public bool IsBlocking { get; set; } = true;

    public string? BlockDestination { get; set; }
    public string? BlockDestinationType { get; set; }

    public List<Profile> AvailableProfiles { get; set; } = new();
    public List<Client> AvailableClients { get; set; } = new();
}
