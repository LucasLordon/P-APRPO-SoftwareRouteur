using System.ComponentModel.DataAnnotations.Schema;

namespace SoftwareRouteur.Models;

[Table("challenge_proofs")]
public class ChallengeProof
{
    [Column("id")]
    public int Id { get; set; }

    [Column("challenge_id")]
    public int ChallengeId { get; set; }
    public Challenge? Challenge { get; set; }

    [Column("proof_type")]
    public required string ProofType { get; set; }

    [Column("file_path")]
    public string? FilePath { get; set; }

    [Column("submitted_at")]
    public DateTime SubmittedAt { get; set; }
}
