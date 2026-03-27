using InfoSec.Common.Models;
using InfoSec.Common.Utils;

namespace InfoSec.Common.Output;

public static class ConsolePrinter
{
    public static void PrintVariantInfo(VariantInfo info)
    {
        Console.WriteLine("=== Параметры варианта ===");
        Console.WriteLine($"Код:    {info.OriginalCode}");
        Console.WriteLine($"Digits: {info.DigitsOnly}");
        Console.WriteLine($"LAST4:  {info.Last4}");
        Console.WriteLine($"LAST2:  {info.Last2}");
        Console.WriteLine($"SUM:    {info.Sum}");
        Console.WriteLine($"SEED:   {info.Seed}");
        Console.WriteLine();
    }

    public static void PrintHex(string title, byte[] data)
    {
        Console.WriteLine($"{title}: {HexUtils.ToHex(data)}");
    }

    public static void PrintLine(string title, string value)
    {
        Console.WriteLine($"{title}: {value}");
    }
}