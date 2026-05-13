using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SoftwareRouteur.Models;

[Table("profiles")]
public class Profile
{
    [Column("id")]
    public int Id { get; set; }

    [Column("display_name")]
    [MaxLength(100)]
    public required string DisplayName { get; set; }

    [Column("role")]
    public required string Role { get; set; }

    [Column("pin_hash")]
    public string? PinHash { get; set; }

    [Column("created_by_id")]
    public int? CreatedById { get; set; }

    [Column("created_at")]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    [Column("opnsense_src_alias_uuid")]
    public string? OpnsenseSrcAliasUuid { get; set; }

    [Column("opnsense_block_alias_uuid")]
    public string? OpnsenseBlockAliasUuid { get; set; }

    [Column("opnsense_allow_alias_uuid")]
    public string? OpnsenseAllowAliasUuid { get; set; }

    [Column("opnsense_block_rule_uuid")]
    public string? OpnsenseBlockRuleUuid { get; set; }

    [Column("opnsense_allow_rule_uuid")]
    public string? OpnsenseAllowRuleUuid { get; set; }

    public Profile? CreatedBy { get; set; }
    public ICollection<Client> Clients { get; set; } = new List<Client>();
    public ICollection<ProfileFirewallRule> ProfileFirewallRules { get; set; } = new List<ProfileFirewallRule>();
}
