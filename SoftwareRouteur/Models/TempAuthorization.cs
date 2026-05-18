using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SoftwareRouteur.Models;

[Table("temp_authorizations")]
public class TempAuthorization
{
    [Column("id")]
    public int Id { get; set; }

    /// <summary>Child profile that benefits from this authorization.</summary>
    [Column("profile_id")]
    public int ProfileId { get; set; }
    public Profile Profile { get; set; } = null!;

    /// <summary>NULL = applies to all devices of the child profile.</summary>
    [Column("client_id")]
    public int? ClientId { get; set; }
    public Client? Client { get; set; }

    [Column("duration_minutes")]
    public int DurationMinutes { get; set; }

    [Column("activated_at")]
    public DateTime ActivatedAt { get; set; } = DateTime.Now;

    /// <summary>Calculated: ActivatedAt + DurationMinutes.</summary>
    [Column("expires_at")]
    public DateTime ExpiresAt { get; set; }

    /// <summary>Parent profile who granted this authorization.</summary>
    [Column("created_by_id")]
    public int CreatedById { get; set; }
    public Profile CreatedBy { get; set; } = null!;

    /// <summary>
    /// Optional specific destination to allow during this authorization.
    /// NULL = unblock all internet access (toggle the main firewall rule).
    /// Non-null = add this destination to the profile allow alias during the window, remove it when the authorization expires.
    /// </summary>
    [Column("allow_destination")]
    [MaxLength(255)]
    public string? AllowDestination { get; set; }

    /// <summary>Type of AllowDestination: "domain", "ip", or "cidr". NULL when AllowDestination is NULL.</summary>
    [Column("allow_destination_type")]
    [MaxLength(10)]
    public string? AllowDestinationType { get; set; }
}
