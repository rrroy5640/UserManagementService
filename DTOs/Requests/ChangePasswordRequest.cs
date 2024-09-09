namespace UserManagementService.DTOs.Requests
{
    public class ChangePasswordRequest
    {
        public required string NewPassword { get; set; }
        public required string OldPassword { get; set; }
    }
}