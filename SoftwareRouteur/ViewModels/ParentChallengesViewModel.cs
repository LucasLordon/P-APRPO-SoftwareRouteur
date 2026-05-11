using SoftwareRouteur.Models;

namespace SoftwareRouteur.ViewModels;

public class ParentChallengesViewModel
{
    public List<Challenge> ActiveChallenges { get; set; } = new();
    public List<Challenge> PendingApproval { get; set; } = new();
    public List<Profile> ChildProfiles { get; set; } = new();
    public int CurrentParentId { get; set; }
}
