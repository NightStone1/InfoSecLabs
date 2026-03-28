using InfoSec.Common.Variant;

namespace Lab2;

internal static class Program
{
    static void Main()
    {
        string studentCode = "22-ФАБ-ИВ109";
        var variant = VariantCalculator.FromStudentCode(studentCode);

        int shift = (variant.Last2 % 25) + 1;
        int keyLen = 4 + (variant.Sum % 3);
        int len = 60 + (variant.Last2 % 21);

        string last2Text = variant.Last2Text;
        string prefix = $"LAB2-{last2Text} ";
        string key = BuildKeyFromLast4(variant.Last4, keyLen);

        Console.WriteLine("=== Вводные данные ===");
        Console.WriteLine($"D={variant.DigitsOnly}");
        Console.WriteLine($"LAST2={variant.Last2Text}");
        Console.WriteLine($"LAST4={variant.Last4}");
        Console.WriteLine($"SUM={variant.Sum}");
        Console.WriteLine($"SEED={variant.Seed}");
        Console.WriteLine($"SHIFT={shift}");
        Console.WriteLine($"KEYLEN={keyLen}");
        Console.WriteLine($"KEY={key}");
        Console.WriteLine($"LEN={len}");
        Console.WriteLine($"PREFIX=\"{prefix}\"");
        Console.WriteLine();

        string plainText = BuildPlainText(prefix, len);
        Console.WriteLine("=== Открытый текст ===");
        Console.WriteLine(plainText);
        Console.WriteLine();

        string caesarCipher = CaesarCipher.Encrypt(plainText, shift);
        string caesarPlain = CaesarCipher.Decrypt(caesarCipher, shift);

        Console.WriteLine("=== Caesar ===");
        Console.WriteLine($"Cipher: {caesarCipher}");
        Console.WriteLine($"Decrypt: {caesarPlain}");
        Console.WriteLine($"Обратимость: {plainText == caesarPlain}");
        Console.WriteLine();

        int recoveredShift = RecoverShiftFromKnownPrefix(prefix, caesarCipher);
        string recoveredText = CaesarCipher.Decrypt(caesarCipher, recoveredShift);

        Console.WriteLine("=== Known-plaintext attack on Caesar ===");
        Console.WriteLine($"Recovered SHIFT = {recoveredShift}");
        Console.WriteLine($"Recovered text = {recoveredText}");
        Console.WriteLine($"Совпадение с P: {recoveredText == plainText}");
        Console.WriteLine();

        string vigenereCipher = VigenereCipher.Encrypt(plainText, key);
        string vigenerePlain = VigenereCipher.Decrypt(vigenereCipher, key);

        Console.WriteLine("=== Vigenere ===");
        Console.WriteLine($"Cipher: {vigenereCipher}");
        Console.WriteLine($"Decrypt: {vigenerePlain}");
        Console.WriteLine($"Обратимость: {plainText == vigenerePlain}");
    }

    private static string BuildKeyFromLast4(string last4, int keyLen)
    {
        string baseKey = string.Concat(last4.Select(d => (char)('A' + (d - '0'))));
        return string.Concat(Enumerable.Range(0, keyLen).Select(i => baseKey[i % baseKey.Length]));
    }

    private static string BuildPlainText(string prefix, int len)
    {
        string tail = "CLASSICAL CIPHERS ARE EDUCATIONAL BUT WEAK AGAINST BASIC ATTACKS.";
        string text = (prefix + tail).ToUpperInvariant();

        if (text.Length > len)
            return text[..len];

        return text.PadRight(len, ' ');
    }

    private static int RecoverShiftFromKnownPrefix(string prefix, string cipherText)
    {
        int i = 0;
        while (i < prefix.Length)
        {
            char p = prefix[i];
            char c = cipherText[i];

            if (p is >= 'A' and <= 'Z' && c is >= 'A' and <= 'Z')
                return (c - p + 26) % 26;

            i++;
        }

        throw new InvalidOperationException("Не удалось восстановить SHIFT по префиксу.");
    }
}