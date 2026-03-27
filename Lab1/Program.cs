using System.Text;
using InfoSec.Common.Output;
using InfoSec.Common.Utils;
using InfoSec.Common.Variant;

namespace Lab1;

internal static class Program
{
    static void Main()
    {
        Console.OutputEncoding = Encoding.UTF8;

        string studentCode = "22-ФАБ-ИВ109";
        var variant = VariantCalculator.FromStudentCode(studentCode);

        int len = 20 + (variant.Last2 % 11);
        int k = 5 + (variant.Sum % 4);

        string prefix = TextUtils.FitToLength($"HELLO_{variant.Last2Text[0]}", k);

        Console.WriteLine("Вводные данные:");
        Console.WriteLine($"D={variant.DigitsOnly}");
        Console.WriteLine($"LAST2={variant.Last2Text}");
        Console.WriteLine($"LAST4={variant.Last4}");
        Console.WriteLine($"SUM={variant.Sum}");
        Console.WriteLine($"SEED={variant.Seed}");
        Console.WriteLine($"LEN={len}");
        Console.WriteLine($"K={k}");
        Console.WriteLine($"PREFIX={prefix}");
        Console.WriteLine();

        string p1Text = TextUtils.FitToLength(prefix + "eto soobchenie sekretno", len);
        string p2Text = TextUtils.FitToLength("eto soobchenie toje sekretno", len);

        Console.WriteLine($"Сообщение p1: {p1Text}");
        Console.WriteLine($"Сообщение p2: {p2Text}");
        Console.WriteLine();

        byte[] p1 = Encoding.ASCII.GetBytes(p1Text);
        byte[] p2 = Encoding.ASCII.GetBytes(p2Text);

        byte[] g = GenerateGamma(variant.Seed, len);

        byte[] c1 = ByteUtils.Xor(p1, g);
        byte[] c2 = ByteUtils.Xor(p2, g);

        Console.WriteLine("Первые 16 байт сообщений P1 и P2:");
        PrintFirst16("P1", p1);
        PrintFirst16("P2", p2);

        Console.WriteLine("Первые 16 байт гаммы G:");
        PrintFirst16("G ", g);

        Console.WriteLine("Первые 16 байт зашифрованных сообщений C1 и C2:");
        PrintFirst16("C1", c1);
        PrintFirst16("C2", c2);
        Console.WriteLine();

        Console.WriteLine("Проверка:");
        byte[] d1 = ByteUtils.Xor(c1, g);
        byte[] d2 = ByteUtils.Xor(c2, g);
        PrintFirst16("D1", d1);
        PrintFirst16("D2", d2);
        Console.WriteLine("Байты совпадают");
        Console.WriteLine();

        Console.WriteLine("Атака:");
        byte[] x = ByteUtils.Xor(c1, c2);
        Console.WriteLine("Первые 16 байт X:");
        PrintFirst16("X ", x);

        byte[] prefixBytes = Encoding.ASCII.GetBytes(prefix);
        byte[] recovered = new byte[k];
        for (int i = 0; i < k; i++)
            recovered[i] = (byte)(x[i] ^ prefixBytes[i]);

        Console.WriteLine("Восстановленный префикс P2:");
        Console.WriteLine(Encoding.ASCII.GetString(recovered));
        Console.WriteLine();

        Console.WriteLine("Исправление:");
        byte[] g2 = GenerateGamma(variant.Seed + 1, len);
        Console.WriteLine("Первые 16 байт новой гаммы G2:");
        PrintFirst16("G2", g2);

        byte[] c2Fixed = ByteUtils.Xor(p2, g2);
        Console.WriteLine("Первые 16 байт зашифрованных сообщений C1 и C2':");
        PrintFirst16("C1 ", c1);
        PrintFirst16("C2'", c2Fixed);
        Console.WriteLine();

        Console.WriteLine("Атака:");
        byte[] xFixed = ByteUtils.Xor(c1, c2Fixed);
        Console.WriteLine("Первые 16 байт X:");
        PrintFirst16("X ", xFixed);

        byte[] badRecovery = new byte[k];
        for (int i = 0; i < k; i++)
            badRecovery[i] = (byte)(xFixed[i] ^ prefixBytes[i]);

        Console.WriteLine("Восстановленное сообщение после исправления:");
        Console.WriteLine($"Совпадение после исправления: {p2Text.StartsWith(Encoding.ASCII.GetString(badRecovery))}");
    }

    private static byte[] GenerateGamma(int seed, int length)
    {
        var rng = new Random(seed);
        byte[] gamma = new byte[length];
        rng.NextBytes(gamma);
        return gamma;
    }

    private static void PrintFirst16(string name, byte[] data)
    {
        Console.Write($"{name}: ");
        for (int i = 0; i < Math.Min(16, data.Length); i++)
            Console.Write($"{data[i]:X2} ");
        Console.WriteLine();
    }
}