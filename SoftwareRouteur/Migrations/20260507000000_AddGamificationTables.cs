using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;
using SoftwareRouteur.Data;

#nullable disable

namespace SoftwareRouteur.Migrations
{
    [DbContext(typeof(AppDbContext))]
    [Migration("20260507000000_AddGamificationTables")]
    public partial class AddGamificationTables : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "is_global",
                table: "firewall_rules",
                type: "tinyint(1)",
                nullable: false,
                defaultValue: false);

            migrationBuilder.CreateTable(
                name: "challenges",
                columns: table => new
                {
                    id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    parent_profile_id = table.Column<int>(type: "int", nullable: false),
                    child_profile_id = table.Column<int>(type: "int", nullable: false),
                    title = table.Column<string>(type: "longtext", nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    description = table.Column<string>(type: "longtext", nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    reward_minutes = table.Column<int>(type: "int", nullable: false),
                    reward_scope = table.Column<string>(type: "longtext", nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    reward_site = table.Column<string>(type: "longtext", nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    status = table.Column<string>(type: "longtext", nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    proof_required = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    created_at = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_challenges", x => x.id);
                    table.ForeignKey(
                        name: "FK_challenges_profiles_child_profile_id",
                        column: x => x.child_profile_id,
                        principalTable: "profiles",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_challenges_profiles_parent_profile_id",
                        column: x => x.parent_profile_id,
                        principalTable: "profiles",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "challenge_proofs",
                columns: table => new
                {
                    id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    challenge_id = table.Column<int>(type: "int", nullable: false),
                    proof_type = table.Column<string>(type: "longtext", nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    file_path = table.Column<string>(type: "longtext", nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    submitted_at = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_challenge_proofs", x => x.id);
                    table.ForeignKey(
                        name: "FK_challenge_proofs_challenges_challenge_id",
                        column: x => x.challenge_id,
                        principalTable: "challenges",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "rewards",
                columns: table => new
                {
                    id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    challenge_id = table.Column<int>(type: "int", nullable: false),
                    child_profile_id = table.Column<int>(type: "int", nullable: false),
                    client_id = table.Column<int>(type: "int", nullable: true),
                    total_minutes = table.Column<int>(type: "int", nullable: false),
                    remaining_seconds = table.Column<int>(type: "int", nullable: false),
                    status = table.Column<string>(type: "longtext", nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    activated_at = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    last_updated_at = table.Column<DateTime>(type: "datetime(6)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_rewards", x => x.id);
                    table.ForeignKey(
                        name: "FK_rewards_challenges_challenge_id",
                        column: x => x.challenge_id,
                        principalTable: "challenges",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_rewards_clients_client_id",
                        column: x => x.client_id,
                        principalTable: "clients",
                        principalColumn: "id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_rewards_profiles_child_profile_id",
                        column: x => x.child_profile_id,
                        principalTable: "profiles",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateIndex(
                name: "IX_challenges_child_profile_id",
                table: "challenges",
                column: "child_profile_id");

            migrationBuilder.CreateIndex(
                name: "IX_challenges_parent_profile_id",
                table: "challenges",
                column: "parent_profile_id");

            migrationBuilder.CreateIndex(
                name: "IX_challenge_proofs_challenge_id",
                table: "challenge_proofs",
                column: "challenge_id");

            migrationBuilder.CreateIndex(
                name: "IX_rewards_challenge_id",
                table: "rewards",
                column: "challenge_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_rewards_child_profile_id",
                table: "rewards",
                column: "child_profile_id");

            migrationBuilder.CreateIndex(
                name: "IX_rewards_client_id",
                table: "rewards",
                column: "client_id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(name: "challenge_proofs");
            migrationBuilder.DropTable(name: "rewards");
            migrationBuilder.DropTable(name: "challenges");

            migrationBuilder.DropColumn(
                name: "is_global",
                table: "firewall_rules");
        }
    }
}
