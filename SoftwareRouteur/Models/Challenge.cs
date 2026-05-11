using System.ComponentModel.DataAnnotations.Schema;

namespace SoftwareRouteur.Models;

[Table("challenges")]
public class Challenge
{
    [Column("id")]
    public int Id { get; set; }

    [Column("parent_profile_id")]
    public int ParentProfileId { get; set; }
    public Profile? ParentProfile { get; set; }

    [Column("child_profile_id")]
    public int ChildProfileId { get; set; }
    public Profile? ChildProfile { get; set; }

    [Column("title")]
    public required string Title { get; set; }

    [Column("description")]
    public string? Description { get; set; }

    [Column("reward_minutes")]
    public int RewardMinutes { get; set; }

    [Column("reward_scope")]
    public required string RewardScope { get; set; }

    [Column("reward_site")]
    public string? RewardSite { get; set; }

    [Column("status")]
    public string Status { get; set; } = "pending";

    [Column("proof_required")]
    public bool ProofRequired { get; set; } = true;

    [Column("created_at")]
    public DateTime CreatedAt { get; set; }

    public List<ChallengeProof> Proofs { get; set; } = new();
    public Reward? Reward { get; set; }
}
