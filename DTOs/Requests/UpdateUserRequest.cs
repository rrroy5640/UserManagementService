namespace UserManagementService.DTOs.Requests
{
    public class UpdateUserRequest
    {
        public required string Email { get; set; }
        public required string Name { get; set; }
    }
}