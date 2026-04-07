using System.Security.Cryptography;
using System.Text;
using InfoSec.Common.Variant;

namespace Lab5;

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

        int len = 80 + (last2 % 41);
        int iter = 50000 + (sum % 10) * 10000;
        int amount = 1000 + (seed % 9000);

        string passText = $"GcmLab5_{last4}";
        string saltText = $"SALT_{last4}";

        byte[] aesKey = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.ASCII.GetBytes(passText),
            Encoding.ASCII.GetBytes(saltText),
            iter,
            HashAlgorithmName.SHA256,
            32);

        byte[] nonce = SHA256.HashData(Encoding.ASCII.GetBytes("NONCE_" + last4))
            .Take(12)
            .ToArray();

        string aadText = $"V=1;ALG=AES-256-GCM;ACC={last4}";
        byte[] aadBytes = Encoding.ASCII.GetBytes(aadText);

        string msgFile = $"msg_{last4}.txt";
        string aadFile = $"aad_{last4}.txt";
        string ciphFile = $"ciph_{last4}.bin";
        string tagFile = $"tag_{last4}.bin";
        string containerFile = $"container_{last4}.txt";
        string decFile = $"dec_{last4}.txt";

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
        Console.WriteLine($"AMOUNT={amount}");
        Console.WriteLine($"PASS={passText}");
        Console.WriteLine($"SALT_TEXT={saltText}");
        Console.WriteLine($"AES_KEY_HEX={ToHex(aesKey)}");
        Console.WriteLine($"NONCE_HEX={ToHex(nonce)}");
        Console.WriteLine($"AAD={aadText}");
        Console.WriteLine();

        // =========================
        // ЧАСТЬ 1 — Подготовка сообщения
        // =========================

        string msgText = BuildMessage(studentCodeAscii, last4, amount, len);

        File.WriteAllText(msgFile, msgText, Encoding.ASCII);
        File.WriteAllText(aadFile, aadText, Encoding.ASCII);

        Console.WriteLine("=== Созданы файлы ===");
        Console.WriteLine(msgFile);
        Console.WriteLine(aadFile);
        Console.WriteLine();

        // =========================
        // ЧАСТЬ 2–4 — Ключ, nonce, AAD, AES-GCM
        // =========================

        byte[] plainBytes = Encoding.ASCII.GetBytes(msgText);
        byte[] cipherBytes = new byte[plainBytes.Length];
        byte[] tagBytes = new byte[16];

        using (var aesGcm = new AesGcm(aesKey, 16))
        {
            aesGcm.Encrypt(nonce, plainBytes, cipherBytes, tagBytes, aadBytes);
        }

        File.WriteAllBytes(ciphFile, cipherBytes);
        File.WriteAllBytes(tagFile, tagBytes);

        Console.WriteLine("=== Шифрование AES-256-GCM ===");
        Console.WriteLine($"cipher bytes: {cipherBytes.Length}");
        Console.WriteLine($"tag bytes: {tagBytes.Length}");
        Console.WriteLine($"CIPHER_HEX={ToHex(cipherBytes)}");
        Console.WriteLine($"TAG_HEX={ToHex(tagBytes)}");
        Console.WriteLine();

        // =========================
        // ЧАСТЬ 5 — Контейнер
        // =========================

        string containerText =
            $"nonce_hex={ToHex(nonce)}{Environment.NewLine}" +
            $"tag_hex={ToHex(tagBytes)}{Environment.NewLine}" +
            $"cipher_hex={ToHex(cipherBytes)}";

        File.WriteAllText(containerFile, containerText, Encoding.ASCII);

        Console.WriteLine("=== Контейнер ===");
        Console.WriteLine(containerText);
        Console.WriteLine();

        // =========================
        // ЧАСТЬ 6 — Проверка и расшифрование
        // =========================

        var parsed = ParseContainer(containerText);

        byte[] decryptedBytes = new byte[parsed.Cipher.Length];
        bool decryptOk = false;

        try
        {
            using var aesGcm = new AesGcm(aesKey, 16);
            aesGcm.Decrypt(parsed.Nonce, parsed.Cipher, parsed.Tag, decryptedBytes, aadBytes);
            decryptOk = true;
        }
        catch (CryptographicException)
        {
            decryptOk = false;
        }

        if (decryptOk)
        {
            string decryptedText = Encoding.ASCII.GetString(decryptedBytes);
            File.WriteAllText(decFile, decryptedText, Encoding.ASCII);

            bool same = msgText == decryptedText;

            Console.WriteLine("=== Проверка и расшифрование ===");
            Console.WriteLine($"Decrypt ok: {decryptOk}");
            Console.WriteLine($"Совпадение dec и msg: {same}");
            Console.WriteLine($"Файл расшифрования: {decFile}");
            Console.WriteLine();
        }
        else
        {
            Console.WriteLine("=== Проверка и расшифрование ===");
            Console.WriteLine("Decrypt ok: False");
            Console.WriteLine();
        }

        // =========================
        // ЧАСТЬ 7 — Атака 1: портим 1 байт cipher_hex
        // =========================

        byte[] tamperedCipher = (byte[])parsed.Cipher.Clone();
        tamperedCipher[0] ^= 0x01;

        string tamperedCipherContainer =
            $"nonce_hex={ToHex(parsed.Nonce)}{Environment.NewLine}" +
            $"tag_hex={ToHex(parsed.Tag)}{Environment.NewLine}" +
            $"cipher_hex={ToHex(tamperedCipher)}";

        File.WriteAllText($"container_{last4}_tamper_cipher.txt", tamperedCipherContainer, Encoding.ASCII);

        bool attack1Ok = TryDecrypt(aesKey, parsed.Nonce, tamperedCipher, parsed.Tag, aadBytes, out _);

        Console.WriteLine("=== Атака 1: изменение 1 байта в cipher_hex ===");
        Console.WriteLine($"Decrypt ok after cipher tamper: {attack1Ok}");
        Console.WriteLine($"Ожидаемая ошибка проверки: {!attack1Ok}");
        Console.WriteLine();

        // =========================
        // ЧАСТЬ 7 — Атака 2: меняем AAD
        // =========================

        string tamperedAadText = aadText.Replace("V=1", "V=2");
        byte[] tamperedAadBytes = Encoding.ASCII.GetBytes(tamperedAadText);
        File.WriteAllText($"aad_{last4}_tampered.txt", tamperedAadText, Encoding.ASCII);

        bool attack2Ok = TryDecrypt(aesKey, parsed.Nonce, parsed.Cipher, parsed.Tag, tamperedAadBytes, out _);

        Console.WriteLine("=== Атака 2: изменение AAD ===");
        Console.WriteLine($"AAD original: {aadText}");
        Console.WriteLine($"AAD tampered: {tamperedAadText}");
        Console.WriteLine($"Decrypt ok after AAD tamper: {attack2Ok}");
        Console.WriteLine($"Ожидаемая ошибка проверки: {!attack2Ok}");
        Console.WriteLine();

        // =========================
        // Для отчёта: команда OpenSSL (как подготовленный артефакт)
        // =========================

        Console.WriteLine("=== Подготовленная команда OpenSSL ===");
        Console.WriteLine(
            $"openssl enc -aes-256-gcm -K {ToHex(aesKey)} -iv {ToHex(nonce)} " +
            $"-aad \"{aadText}\" -in {msgFile} -out {ciphFile} -tag {tagFile}");
        Console.WriteLine();
        Console.WriteLine("Примечание: в данной среде CLI openssl enc не поддержал нужный AEAD-синтаксис,");
        Console.WriteLine("поэтому шифрование и проверка выполнены программно через AesGcm.");
    }

    private static string BuildMessage(string studentCode, string last4, int amount, int len)
    {
        string requiredLine = $"TRANSFER {amount} TO ACCOUNT {last4}";
        string text =
            $"Variant: {studentCode}{Environment.NewLine}" +
            $"AEAD laboratory work.{Environment.NewLine}" +
            $"{requiredLine}{Environment.NewLine}" +
            $"Integrity and authenticity are verified by GCM.{Environment.NewLine}";

        if (text.Length > len)
            return text[..len];

        return text.PadRight(len, 'A');
    }

    private static bool TryDecrypt(
        byte[] key,
        byte[] nonce,
        byte[] cipher,
        byte[] tag,
        byte[] aad,
        out byte[] plain)
    {
        plain = new byte[cipher.Length];

        try
        {
            using var aesGcm = new AesGcm(key, 16);
            aesGcm.Decrypt(nonce, cipher, tag, plain, aad);
            return true;
        }
        catch (CryptographicException)
        {
            plain = Array.Empty<byte>();
            return false;
        }
    }

    private static (byte[] Nonce, byte[] Tag, byte[] Cipher) ParseContainer(string containerText)
    {
        string[] lines = containerText
            .Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);

        string nonceHex = lines.Single(x => x.StartsWith("nonce_hex=", StringComparison.Ordinal))["nonce_hex=".Length..];
        string tagHex = lines.Single(x => x.StartsWith("tag_hex=", StringComparison.Ordinal))["tag_hex=".Length..];
        string cipherHex = lines.Single(x => x.StartsWith("cipher_hex=", StringComparison.Ordinal))["cipher_hex=".Length..];

        return (
            Convert.FromHexString(nonceHex),
            Convert.FromHexString(tagHex),
            Convert.FromHexString(cipherHex)
        );
    }

    private static string ToHex(byte[] data)
    {
        return Convert.ToHexString(data).ToLowerInvariant();
    }
}