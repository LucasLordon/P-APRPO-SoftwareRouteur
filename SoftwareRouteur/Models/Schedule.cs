using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SoftwareRouteur.Models;

[Table("schedules")]
public class Schedule
{
    [Column("id")]
    public int Id { get; set; }

    /// <summary>NULL = global schedule (applies to whole household)</summary>
    [Column("profile_id")]
    public int? ProfileId { get; set; }
    public Profile? Profile { get; set; }

    /// <summary>NULL = applies to all devices of the profile</summary>
    [Column("client_id")]
    public int? ClientId { get; set; }
    public Client? Client { get; set; }

    [Column("time_start")]
    public TimeOnly TimeStart { get; set; }

    [Column("time_end")]
    public TimeOnly TimeEnd { get; set; }

    /// <summary>7-char bitmask: position 0=Mon 1=Tue 2=Wed 3=Thu 4=Fri 5=Sat 6=Sun. Example: "1111100" = Mon–Fri.</summary>
    [Column("days")]
    [MaxLength(7)]
    public required string Days { get; set; }

    /// <summary>true = block during this window; false = allow during this window</summary>
    [Column("is_blocking")]
    public bool IsBlocking { get; set; } = true;

    /// <summary>
    /// Optional specific destination to block/allow during this schedule.
    /// NULL = block all internet access (toggle the main firewall rule).
    /// Non-null = add this destination to the profile blocklist alias during the window, remove it when the window ends.
    /// </summary>
    [Column("block_destination")]
    [MaxLength(255)]
    public string? BlockDestination { get; set; }

    /// <summary>Type of BlockDestination: "domain", "ip", or "cidr". NULL when BlockDestination is NULL.</summary>
    [Column("block_destination_type")]
    [MaxLength(10)]
    public string? BlockDestinationType { get; set; }

    [Column("created_at")]
    public DateTime CreatedAt { get; set; } = DateTime.Now;
}
