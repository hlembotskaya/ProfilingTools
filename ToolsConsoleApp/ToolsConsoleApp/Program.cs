using System;
using System.Security.Cryptography;

class Task1
{
    public static void Main()
    {
        byte[] salt = GenerateSalt(16);
        var hash = GeneratePasswordHashUsingSalt("password", salt);
        var hashFixed = FixedGeneratePasswordHashUsingSalt("password", salt);

        Console.WriteLine($"Hash: {hash}");

        Console.WriteLine($"Fixed Hash: {hashFixed}"); 
    }

    public static string GeneratePasswordHashUsingSalt(string passwordText, byte[] salt)
    {
        var iterate = 10000;
        var pbkdf2 = new Rfc2898DeriveBytes(passwordText, salt, iterate);
        byte[] hash = pbkdf2.GetBytes(20);

        byte[] hashBytes = new byte[36];
        Array.Copy(salt, 0, hashBytes, 0, 16);
        Array.Copy(hash, 0, hashBytes, 16, 20);

        var passwordHash = Convert.ToBase64String(hashBytes);

        return passwordHash;
    }

    public static string FixedGeneratePasswordHashUsingSalt(string passwordText, byte[] salt)
    {
        var iterate = 10000;

        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(passwordText, salt, iterate, HashAlgorithmName.SHA256, 20);

        byte[] hashBytes = new byte[36];
        Buffer.BlockCopy(salt, 0, hashBytes, 0, 16); 
        Buffer.BlockCopy(hash, 0, hashBytes, 16, 20);

        var passwordHash = Convert.ToBase64String(hashBytes);

        return passwordHash;
    }

    public static byte[] GenerateSalt(int size)
    {
        using (var rng = RandomNumberGenerator.Create())
        {
            byte[] salt = new byte[size];
            rng.GetBytes(salt);
            return salt;
        }
    }
}
