using SoftwareRouteur.Models;

namespace SoftwareRouteur.ViewModels;

public class ParentReglesViewModel
{
    public List<Profile> ChildProfiles { get; set; } = new();
    public List<Client> AllClients { get; set; } = new();
    public int? SelectedProfileId { get; set; }
}
