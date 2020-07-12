namespace iAuth
{
    public abstract class Authmodel
    {
        public virtual string Email { get; set; }
        public byte[] PasswordHash { get; set; }
        public byte[] PasswordSalt { get; set; }
    }
}
