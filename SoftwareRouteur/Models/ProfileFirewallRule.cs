using System.ComponentModel.DataAnnotations.Schema;

namespace SoftwareRouteur.Models;

[Table("profile_firewall_rules")]
public class ProfileFirewallRule
{
    [Column("id")]
    public int Id { get; set; }

    [Column("profile_id")]
    public int ProfileId { get; set; }

    [Column("rule_type")]
    public required string RuleType { get; set; }

    [Column("destination")]
    public required string Destination { get; set; }

    [Column("action")]
    public required string Action { get; set; }

    [Column("created_at")]
    public DateTime CreatedAt { get; set; }

    public Profile? Profile { get; set; }
}
