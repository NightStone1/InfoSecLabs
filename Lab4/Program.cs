using System.Security.Cryptography;
using System.Text;
using InfoSec.Common.Variant;

namespace Lab4;

internal class Program
{
    static void Main()
    {
        Console.OutputEncoding = Encoding.UTF8;

        string studentCode = "22-ФАБ-ИВ109";
        var variant = VariantCalculator.FromStudentCode(studentCode);

        int last2 = variant.Last2;
        string last2Text = variant.Last2Text;
        string last4 = variant.Last4;
        int sum = variant.Sum;
        int seed = variant.Seed;

        int len = 80 + (last2 % 41);
        const string alg = "SHA-256";
        int saltLen = 8 + (last2 % 9);
        int iter = 50000 + (sum % 10) * 10000;
        int msgAmount = 1000 + (seed % 9000);

        Console.WriteLine("=== Вводные данные ===");
        Console.WriteLine($"D={variant.DigitsOnly}");
        Console.WriteLine($"LAST2={last2Text}");
        Console.WriteLine($"LAST4={last4}");
        Console.WriteLine($"SUM={sum}");
        Console.WriteLine($"SEED={seed}");
        Console.WriteLine($"LEN={len}");
        Console.WriteLine($"ALG={alg}");
        Console.WriteLine($"SALT_LEN={saltLen}");
        Console.WriteLine($"ITER={iter}");
        Console.WriteLine($"MSG_AMOUNT={msgAmount}");
        Console.WriteLine();

        // =========================
        // ЧАСТЬ 1 — Целостность файла (SHA-256)
        // =========================

        string fileName = $"file_{last4}.txt";
        string fileContent = BuildFileContent(studentCode, len);

        File.WriteAllText(fileName, fileContent, Encoding.ASCII);

        byte[] originalFileBytes = File.ReadAllBytes(fileName);
        byte[] fileHash1 = SHA256.HashData(originalFileBytes);

        Console.WriteLine("=== SHA-256 файла ===");
        Console.WriteLine($"Файл: {fileName}");
        Console.WriteLine($"HASH1: {ToHex(fileHash1)}");
        Console.WriteLine("OpenSSL:");
        Console.WriteLine($"openssl dgst -sha256 {fileName}");
        Console.WriteLine();

        string modifiedContent = ReplaceOneAsciiChar(fileContent);
        File.WriteAllText(fileName, modifiedContent, Encoding.ASCII);

        byte[] modifiedFileBytes = File.ReadAllBytes(fileName);
        byte[] fileHash2 = SHA256.HashData(modifiedFileBytes);

        Console.WriteLine("=== После изменения одного символа ===");
        Console.WriteLine($"HASH2: {ToHex(fileHash2)}");
        Console.WriteLine($"Изменился: {!fileHash1.SequenceEqual(fileHash2)}");
        Console.WriteLine("OpenSSL:");
        Console.WriteLine($"openssl dgst -sha256 {fileName}");
        Console.WriteLine();

        // =========================
        // ЧАСТЬ 2 — Почему hash рядом с сообщением не защищает
        // =========================

        string message1 = $"TRANSFER {msgAmount} TO ACCOUNT {last4}";
        byte[] hashMessage1 = SHA256.HashData(Encoding.ASCII.GetBytes(message1));

        string message2 = $"TRANSFER {msgAmount + 1} TO ACCOUNT {last4}";
        byte[] hashMessage2 = SHA256.HashData(Encoding.ASCII.GetBytes(message2));

        Console.WriteLine("=== Hash без защиты ===");
        Console.WriteLine($"M1: {message1}");
        Console.WriteLine($"H1: {ToHex(hashMessage1)}");
        Console.WriteLine();

        Console.WriteLine("=== Подмена ===");
        Console.WriteLine($"M2: {message2}");
        Console.WriteLine($"H2: {ToHex(hashMessage2)}");
        Console.WriteLine();

        // =========================
        // ЧАСТЬ 3 — HMAC-SHA-256
        // =========================

        byte[] key = RandomNumberGenerator.GetBytes(16);
        byte[] tag = HMACSHA256.HashData(key, Encoding.ASCII.GetBytes(message1));

        Console.WriteLine("=== HMAC ===");
        Console.WriteLine($"KEY (first 4 bytes): {ToHex(key.Take(4).ToArray())}");
        Console.WriteLine($"TAG: {ToHex(tag)}");
        Console.WriteLine($"Verify (original): {VerifyHmac(key, message1, tag)}");
        Console.WriteLine($"Verify (modified): {VerifyHmac(key, message2, tag)}");
        Console.WriteLine();

        // =========================
        // ЧАСТЬ 4 — PBKDF2 + salt
        // =========================

        byte[] salt = RandomNumberGenerator.GetBytes(saltLen);

        // Для автоматической проверки без ввода с клавиатуры
        string password = "Password123";
        string password2Correct = "Password123";
        string password2Wrong = "WrongPass123";

        byte[] dk = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.ASCII.GetBytes(password),
            salt,
            iter,
            HashAlgorithmName.SHA256,
            32);

        string userRecord = $"iter={iter}; salt_hex={ToHex(salt)}; dk_hex={ToHex(dk)}";
        string userRecordFile = $"user_record_{last4}.txt";
        File.WriteAllText(userRecordFile, userRecord, Encoding.ASCII);

        Console.WriteLine("=== PBKDF2 ===");
        Console.WriteLine($"salt: {ToHex(salt)}");
        Console.WriteLine($"dk: {ToHex(dk)}");
        Console.WriteLine($"record: {userRecord}");
        Console.WriteLine($"record file: {userRecordFile}");
        Console.WriteLine($"Correct password: {VerifyPassword(password2Correct, salt, dk, iter)}");
        Console.WriteLine($"Wrong password: {VerifyPassword(password2Wrong, salt, dk, iter)}");
    }

    private static string BuildFileContent(string studentCode, int totalLen)
    {
        string firstLine = $"Variant: {studentCode}";
        string tail = " Integrity check demo file for SHA-256 and HMAC in laboratory work four.";

        string content = firstLine + Environment.NewLine + tail;

        if (content.Length > totalLen)
            return content[..totalLen];

        return content.PadRight(totalLen, '.');
    }

    private static string ReplaceOneAsciiChar(string text)
    {
        char[] chars = text.ToCharArray();

        for (int i = chars.Length - 1; i >= 0; i--)
        {
            if (chars[i] == '\n' || chars[i] == '\r')
                continue;

            chars[i] = chars[i] == '1' ? '2' : '1';
            return new string(chars);
        }

        throw new InvalidOperationException("Не удалось изменить символ в тексте.");
    }

    private static bool VerifyHmac(byte[] key, string message, byte[] tag)
    {
        byte[] computedTag = HMACSHA256.HashData(key, Encoding.ASCII.GetBytes(message));
        return CryptographicOperations.FixedTimeEquals(computedTag, tag);
    }

    private static bool VerifyPassword(string password, byte[] salt, byte[] expectedDk, int iter)
    {
        byte[] candidateDk = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.ASCII.GetBytes(password),
            salt,
            iter,
            HashAlgorithmName.SHA256,
            32);

        return CryptographicOperations.FixedTimeEquals(candidateDk, expectedDk);
    }

    private static string ToHex(byte[] data)
    {
        return Convert.ToHexString(data).ToLowerInvariant();
    }
}