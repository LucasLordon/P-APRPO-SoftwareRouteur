using SoftwareRouteur.Models;

namespace SoftwareRouteur.ViewModels;

public class ParentSchedulesViewModel
{
    public List<Schedule> Schedules { get; set; } = new();
    public List<TempAuthorization> TempAuthorizations { get; set; } = new();
    public ScheduleCreateViewModel CreateScheduleVm { get; set; } = new();
    public TempAuthCreateViewModel CreateTempAuthVm { get; set; } = new();
}
