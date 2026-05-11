using System.ComponentModel.DataAnnotations.Schema;

namespace SoftwareRouteur.Models;

[Table("rewards")]
public class Reward
{
    [Column("id")]
    public int Id { get; set; }

    [Column("challenge_id")]
    public int ChallengeId { get; set; }
    public Challenge? Challenge { get; set; }

    [Column("child_profile_id")]
    public int ChildProfileId { get; set; }
    public Profile? ChildProfile { get; set; }

    [Column("client_id")]
    public int? ClientId { get; set; }
    public Client? Client { get; set; }

    [Column("total_minutes")]
    public int TotalMinutes { get; set; }

    [Column("remaining_seconds")]
    public int RemainingSeconds { get; set; }

    [Column("status")]
    public string Status { get; set; } = "idle";

    [Column("activated_at")]
    public DateTime? ActivatedAt { get; set; }

    [Column("last_updated_at")]
    public DateTime? LastUpdatedAt { get; set; }
}
