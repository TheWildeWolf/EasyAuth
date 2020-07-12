using Microsoft.EntityFrameworkCore;
using System;
using System.Threading.Tasks;

namespace iAuth
{
    /// <summary>
    /// Default Authservice 
    /// </summary>
    /// <typeparam name="T">Base Entity for authmodel</typeparam>
    /// <typeparam name="D">Db Context</typeparam>
    public abstract class AuthService<T,D> : IAuthService<T> where D:DbContext where T:Authmodel
    {
        private readonly D _db;
        private DbSet<T> entities;
        public AuthService(D context)
        {
            entities = context.Set<T>();
            _db = context;
        }

        public async Task<bool> UserExists(string email)
        {
            if (await entities.AnyAsync(x => x.Email == email))
                return true;

            return false;
        }

        public async Task<bool> Update(T User, string password, string newPassword = null)
        {

            if (!VerifyPasswordHash(password, User.PasswordHash, User.PasswordSalt))
                return false;

            if (newPassword != null)
            {
                CreatePasswordHash(newPassword, out var passwordHash, out var passwordSalt);
                User.PasswordHash = passwordHash;
                User.PasswordSalt = passwordSalt;
            }

            _db.Update(User);
            try
            {
                await _db.SaveChangesAsync();
                return true;
            }
            catch (Exception e)
            {
                throw e;
            }

        }

        public async Task<bool> ResetPassword(T user, string password)
        {
            if (password != null)
            {
                CreatePasswordHash(password, out var passwordHash, out var passwordSalt);
                user.PasswordHash = passwordHash;
                user.PasswordSalt = passwordSalt;
            }
            _db.Update(user);
            try
            {
                await _db.SaveChangesAsync();
                return true;
            }
            catch (Exception e)
            {
                throw e;
            }
        }

        public async Task<T> Login(string username, string password)
        {
            var user = await entities.FirstOrDefaultAsync(x => x.Email == username);
            if (user == null)
                return null;
            if (!VerifyPasswordHash(password, user.PasswordHash, user.PasswordSalt))
                return null;
            return user;
        }

        internal bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new System.Security.Cryptography.HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                for (int i = 0; i < computedHash.Length; i++)
                {
                    if (computedHash[i] != passwordHash[i]) return false;
                }
                return true;
            }
        }

        internal void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new System.Security.Cryptography.HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        public async Task<bool> Create(T user, string password)
        {

            try
            {
                if (!string.IsNullOrEmpty(password))
                {
                    CreatePasswordHash(password, out var passwordHash, out var passwordSalt);
                    user.PasswordHash = passwordHash;
                    user.PasswordSalt = passwordSalt;
                }
                await _db.SaveChangesAsync();
                return true;
            }
            catch (Exception e)
            {
                return false;
            }
        }
    }
}
