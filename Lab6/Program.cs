using System.Security.Cryptography;
using System.Text;
using InfoSec.Common.Variant;

namespace Lab6;

internal class Program
{
    static void Main()
    {
        Console.OutputEncoding = Encoding.UTF8;

        string studentCode = "22-ФАБ-ИВ109";
        string studentCodeAscii = "22-FAB-IV109";

        var variant = VariantCalculator.FromStudentCode(studentCode);

        int last2 = variant.Last2;
        string last2Text = variant.Last2Text;
        string last4 = variant.Last4;
        int sum = variant.Sum;
        int seed = variant.Seed;

        int len = 140 + (last2 % 61);
        int iter = 60000 + (sum % 7) * 10000;
        string saltText = $"SALT_{last4}";
        string passText = $"EncLab6_{last4}";
        int amount = 1000 + (seed % 9000);

        byte[] keyMaterial = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.ASCII.GetBytes(passText),
            Encoding.ASCII.GetBytes(saltText),
            iter,
            HashAlgorithmName.SHA256,
            64);

        byte[] aesKey = keyMaterial[..32];
        byte[] macKey = keyMaterial[32..64];

        byte[] iv = SHA256.HashData(Encoding.ASCII.GetBytes("IV_" + passText))
            .Take(16)
            .ToArray();

        string msgFile = $"msg_{last4}.txt";
        string cbcFile = $"cbc_{last4}.bin";
        string decFile = $"dec_{last4}.txt";
        string tagFile = $"tag_{last4}.txt";
        string tamperedFile = $"cbc_{last4}_tampered.bin";
        string decTamperedFile = $"dec_tampered_{last4}.txt";

        Console.WriteLine("=== Вводные данные ===");
        Console.WriteLine($"Variant original={studentCode}");
        Console.WriteLine($"Variant ASCII={studentCodeAscii}");
        Console.WriteLine($"D={variant.DigitsOnly}");
        Console.WriteLine($"LAST2={last2Text}");
        Console.WriteLine($"LAST4={last4}");
        Console.WriteLine($"SUM={sum}");
        Console.WriteLine($"SEED={seed}");
        Console.WriteLine($"LEN={len}");
        Console.WriteLine($"ITER={iter}");
        Console.WriteLine($"SALT_TEXT={saltText}");
        Console.WriteLine($"PASS={passText}");
        Console.WriteLine($"AMOUNT={amount}");
        Console.WriteLine($"AES_KEY_HEX={ToHex(aesKey)}");
        Console.WriteLine($"IV_HEX={ToHex(iv)}");
        Console.WriteLine($"MAC_KEY_HEX(first 4 bytes)={ToHex(macKey.Take(4).ToArray())}");
        Console.WriteLine();

        // =========================
        // ЧАСТЬ 1 — Входной файл
        // =========================

        string msgText = BuildMessage(studentCodeAscii, last4, amount, len);
        File.WriteAllText(msgFile, msgText, Encoding.ASCII);

        Console.WriteLine("=== Создан файл сообщения ===");
        Console.WriteLine(msgFile);
        Console.WriteLine();

        // =========================
        // ЧАСТЬ 2–3 — AES-256-CBC
        // =========================

        byte[] plainBytes = Encoding.ASCII.GetBytes(msgText);
        byte[] cipherBytes = EncryptAesCbc(plainBytes, aesKey, iv);
        File.WriteAllBytes(cbcFile, cipherBytes);

        byte[] decryptedBytes = DecryptAesCbc(cipherBytes, aesKey, iv);
        string decryptedText = Encoding.ASCII.GetString(decryptedBytes);
        File.WriteAllText(decFile, decryptedText, Encoding.ASCII);

        Console.WriteLine("=== AES-256-CBC ===");
        Console.WriteLine($"cipher bytes: {cipherBytes.Length}");
        Console.WriteLine($"Совпадение dec и msg: {decryptedText == msgText}");
        Console.WriteLine($"Файл шифртекста: {cbcFile}");
        Console.WriteLine($"Файл расшифрования: {decFile}");
        Console.WriteLine();

        Console.WriteLine("=== Команды OpenSSL ===");
        Console.WriteLine(
            $"openssl enc -aes-256-cbc -K {ToHex(aesKey)} -iv {ToHex(iv)} -in {msgFile} -out {cbcFile}");
        Console.WriteLine(
            $"openssl enc -d -aes-256-cbc -K {ToHex(aesKey)} -iv {ToHex(iv)} -in {cbcFile} -out {decFile}");
        Console.WriteLine();

        // =========================
        // ЧАСТЬ 4 — HMAC по IV || ciphertext
        // =========================

        byte[] tag = ComputeHmac(macKey, iv, cipherBytes);
        string tagHex = ToHex(tag);
        File.WriteAllText(tagFile, tagHex, Encoding.ASCII);

        bool verifyOriginal = VerifyHmac(macKey, iv, cipherBytes, tag);

        Console.WriteLine("=== HMAC ===");
        Console.WriteLine($"TAG={tagHex}");
        Console.WriteLine($"Verify original: {verifyOriginal}");
        Console.WriteLine($"Файл тега: {tagFile}");
        Console.WriteLine();

        // =========================
        // ЧАСТЬ 5 — Атака: портим 1 байт
        // =========================

        byte[] tamperedCipher = (byte[])cipherBytes.Clone();
        int middleIndex = tamperedCipher.Length / 2;
        tamperedCipher[middleIndex] ^= 0x01;
        File.WriteAllBytes(tamperedFile, tamperedCipher);

        Console.WriteLine("=== Атака: подмена 1 байта шифртекста ===");
        Console.WriteLine($"Изменён индекс: {middleIndex}");
        Console.WriteLine($"Tampered file: {tamperedFile}");
        Console.WriteLine();

        // Неправильный сценарий: decrypt без verify
        Console.WriteLine("=== Неправильный порядок: decrypt без verify ===");
        bool decryptTamperedOk = TryDecryptAesCbc(tamperedCipher, aesKey, iv, out byte[] tamperedPlain);
        Console.WriteLine($"Decrypt tampered without HMAC verify: {decryptTamperedOk}");

        if (decryptTamperedOk)
        {
            string tamperedText = Encoding.ASCII.GetString(tamperedPlain);
            File.WriteAllText(decTamperedFile, tamperedText, Encoding.ASCII);
            Console.WriteLine($"Файл результата: {decTamperedFile}");
        }
        else
        {
            Console.WriteLine("Расшифрование завершилось ошибкой padding.");
        }

        Console.WriteLine();

        // Правильный сценарий: verify -> decrypt
        Console.WriteLine("=== Правильный порядок: verify -> decrypt ===");
        bool verifyTampered = VerifyHmac(macKey, iv, tamperedCipher, tag);
        Console.WriteLine($"Verify tampered: {verifyTampered}");

        if (!verifyTampered)
        {
            Console.WriteLine("STOP: tampered");
        }
        else
        {
            bool decOk = TryDecryptAesCbc(tamperedCipher, aesKey, iv, out _);
            Console.WriteLine($"Decrypt after verify: {decOk}");
        }
    }

    private static string BuildMessage(string studentCodeAscii, string last4, int amount, int len)
    {
        string requiredLine = $"TRANSFER {amount} TO ACCOUNT {last4}";
        string text =
            $"Variant: {studentCodeAscii}{Environment.NewLine}" +
            $"CBC plus HMAC laboratory work.{Environment.NewLine}" +
            $"{requiredLine}{Environment.NewLine}" +
            $"Integrity must be checked before decryption in secure systems.{Environment.NewLine}";

        if (text.Length > len)
            return text[..len];

        return text.PadRight(len, 'A');
    }

    private static byte[] EncryptAesCbc(byte[] plain, byte[] key, byte[] iv)
    {
        using Aes aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using ICryptoTransform encryptor = aes.CreateEncryptor();
        return encryptor.TransformFinalBlock(plain, 0, plain.Length);
    }

    private static byte[] DecryptAesCbc(byte[] cipher, byte[] key, byte[] iv)
    {
        using Aes aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using ICryptoTransform decryptor = aes.CreateDecryptor();
        return decryptor.TransformFinalBlock(cipher, 0, cipher.Length);
    }

    private static bool TryDecryptAesCbc(byte[] cipher, byte[] key, byte[] iv, out byte[] plain)
    {
        try
        {
            plain = DecryptAesCbc(cipher, key, iv);
            return true;
        }
        catch (CryptographicException)
        {
            plain = Array.Empty<byte>();
            return false;
        }
    }

    private static byte[] ComputeHmac(byte[] macKey, byte[] iv, byte[] cipher)
    {
        byte[] data = new byte[iv.Length + cipher.Length];
        Buffer.BlockCopy(iv, 0, data, 0, iv.Length);
        Buffer.BlockCopy(cipher, 0, data, iv.Length, cipher.Length);

        return HMACSHA256.HashData(macKey, data);
    }

    private static bool VerifyHmac(byte[] macKey, byte[] iv, byte[] cipher, byte[] expectedTag)
    {
        byte[] actualTag = ComputeHmac(macKey, iv, cipher);
        return CryptographicOperations.FixedTimeEquals(actualTag, expectedTag);
    }

    private static string ToHex(byte[] data)
    {
        return Convert.ToHexString(data).ToLowerInvariant();
    }
}