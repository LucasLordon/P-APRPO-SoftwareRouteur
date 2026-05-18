using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftwareRouteur.Migrations
{
    /// <inheritdoc />
    public partial class AddScheduleBlockDestination : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "block_destination",
                table: "schedules",
                type: "varchar(255)",
                maxLength: 255,
                nullable: true)
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.AddColumn<string>(
                name: "block_destination_type",
                table: "schedules",
                type: "varchar(10)",
                maxLength: 10,
                nullable: true)
                .Annotation("MySql:CharSet", "utf8mb4");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "block_destination",
                table: "schedules");

            migrationBuilder.DropColumn(
                name: "block_destination_type",
                table: "schedules");
        }
    }
}
