using MongoDB.Bson;
using MongoDB.Driver;
using UserManagementService.Models;

namespace UserManagementService.Services
{
    public class UserService
    {
        private readonly IMongoCollection<User> _users;

        public UserService(IMongoDBSettings settings)
        {
            var client = new MongoClient(settings.ConnectionString);
            var database = client.GetDatabase(settings.DatabaseName);

            _users = database.GetCollection<User>("Users");
        }

        public User Get(string email)
        {
            return _users.Find(user => user.Email == email).FirstOrDefault();
        }

        public User Create(User user)
        {
            _users.InsertOne(user);
            return user;
        }

        public void Update(string email, User userIn)
        {
            _users.ReplaceOne(user => user.Email == email, userIn);
        }

        public void Remove(User userIn)
        {
            _users.DeleteOne(user => user.Email == userIn.Email);
        }

        public List<User> Search(string query)
        {
            var filter = Builders<User>.Filter.Or(
                Builders<User>.Filter.Regex("Name", new BsonRegularExpression(query, "i")),
                Builders<User>.Filter.Regex("Email", new BsonRegularExpression(query, "i"))
            );

            return _users.Find(filter).ToList();
        }
    }
}