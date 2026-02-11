using System.ComponentModel.DataAnnotations.Schema;

namespace SoftwareRouteur.Models;

[Table("admin_users")]
public class AdminUser
{
    [Column("id")]
    public int Id { get; set; }
    [Column("username")]
    public string Username { get; set; }
    [Column("password_hash")]
    public string PasswordHash { get; set; }
    [Column("created_at")]
    public DateTime CreatedAt { get; set; }
}
