using SoftwareRouteur.Models;

namespace SoftwareRouteur.ViewModels;

public class ChildHomeViewModel
{
    public Profile CurrentProfile { get; set; } = null!;
    public List<Client> AssignedClients { get; set; } = new();
    public Reward? ActiveReward { get; set; }
    public List<Reward> AvailableRewards { get; set; } = new();
}
