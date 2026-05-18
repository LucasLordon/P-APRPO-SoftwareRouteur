using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SoftwareRouteur.Migrations
{
    /// <inheritdoc />
    public partial class AddTempAuthAllowDestination : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "allow_destination",
                table: "temp_authorizations",
                type: "varchar(255)",
                maxLength: 255,
                nullable: true)
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.AddColumn<string>(
                name: "allow_destination_type",
                table: "temp_authorizations",
                type: "varchar(10)",
                maxLength: 10,
                nullable: true)
                .Annotation("MySql:CharSet", "utf8mb4");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "allow_destination",
                table: "temp_authorizations");

            migrationBuilder.DropColumn(
                name: "allow_destination_type",
                table: "temp_authorizations");
        }
    }
}
