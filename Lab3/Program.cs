using System.Security.Cryptography;
using InfoSec.Common.Variant;

namespace Lab3;

internal static class Program
{
    static void Main()
    {
        string studentCode = "22-ФАБ-ИВ109";
        var variant = VariantCalculator.FromStudentCode(studentCode);

        int seed = variant.Seed;
        int tokenLen = 16; // длина токена в байтах
        int N = 10;        // количество токенов

        Console.WriteLine($"Вариант: {studentCode}");
        Console.WriteLine($"TOKEN_LEN={tokenLen}");
        Console.WriteLine($"N={N}");
        Console.WriteLine($"SEED={seed}");
        Console.WriteLine();

        // =========================
        // Часть 2 — генерация токенов
        // =========================

        var prngTokens = new List<string>();
        var csprngTokens = new List<string>();

        for (int i = 0; i < N; i++)
        {
            prngTokens.Add(TokenPRNG(seed + i, tokenLen));
            csprngTokens.Add(TokenCSPRNG(tokenLen));
        }

        Console.WriteLine("=== Первые 5 PRNG токенов ===");
        foreach (var t in prngTokens.Take(5))
            Console.WriteLine(t);

        Console.WriteLine();

        Console.WriteLine("=== Первые 5 CSPRNG токенов ===");
        foreach (var t in csprngTokens.Take(5))
            Console.WriteLine(t);

        Console.WriteLine();

        // =========================
        // Сохранение в файлы
        // =========================

        File.WriteAllLines($"prng_tokens_{variant.Last4}.txt", prngTokens);
        File.WriteAllLines($"csprng_tokens_{variant.Last4}.txt", csprngTokens);

        // =========================
        // Часть 3 — уязвимость PRNG
        // =========================

        Console.WriteLine("=== Уязвимость PRNG ===");

        string tokenA = TokenPRNG(seed, tokenLen);
        string tokenB = TokenPRNG(seed, tokenLen);

        Console.WriteLine($"token_A: {tokenA}");
        Console.WriteLine($"token_B: {tokenB}");
        Console.WriteLine($"Совпадение: {tokenA == tokenB}");

        Console.WriteLine();

        // атака
        string attacker = AttackerRebuild(seed, tokenLen);

        Console.WriteLine("=== Атака ===");
        Console.WriteLine($"attacker: {attacker}");
        Console.WriteLine($"Совпадение с token_A: {attacker == tokenA}");

        Console.WriteLine();

        // =========================
        // Часть 4 — исправление (CSPRNG)
        // =========================

        Console.WriteLine("=== Исправление (CSPRNG) ===");

        string safeA = TokenCSPRNG(tokenLen);
        string safeB = TokenCSPRNG(tokenLen);

        Console.WriteLine($"token_A: {safeA}");
        Console.WriteLine($"token_B: {safeB}");
        Console.WriteLine($"Совпадение: {safeA == safeB}");
    }

    // =========================
    // PRNG токен
    // =========================
    static string TokenPRNG(int seed, int len)
    {
        var random = new Random(seed);
        byte[] data = new byte[len];
        random.NextBytes(data);
        return ToHex(data);
    }

    // =========================
    // CSPRNG токен
    // =========================
    static string TokenCSPRNG(int len)
    {
        byte[] data = new byte[len];
        RandomNumberGenerator.Fill(data);
        return ToHex(data);
    }

    // =========================
    // атака
    // =========================
    static string AttackerRebuild(int seed, int len)
    {
        return TokenPRNG(seed, len);
    }

    static string ToHex(byte[] data)
    {
        return BitConverter.ToString(data);
    }
}