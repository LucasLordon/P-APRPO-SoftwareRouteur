using SoftwareRouteur.Models;

namespace SoftwareRouteur.ViewModels;

public class ChildChallengesViewModel
{
    public Profile CurrentProfile { get; set; } = null!;
    public List<Challenge> MyChallenges { get; set; } = new();
    public List<Profile> ParentProfiles { get; set; } = new();
}
