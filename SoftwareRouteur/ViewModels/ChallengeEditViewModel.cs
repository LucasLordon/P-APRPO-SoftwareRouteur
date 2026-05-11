namespace SoftwareRouteur.ViewModels;

public class ChallengeEditViewModel
{
    public int Id { get; set; }
    public string Title { get; set; } = "";
    public string? Description { get; set; }
    public int RewardMinutes { get; set; }
    public string RewardScope { get; set; } = "global";
    public string? RewardSite { get; set; }
    public bool ProofRequired { get; set; }
    public int ChildProfileId { get; set; }
}
