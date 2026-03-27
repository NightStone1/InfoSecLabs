using System.Text;
using InfoSec.Common.Models;

namespace InfoSec.Common.Variant;

public static class VariantCalculator
{
    public static VariantInfo FromStudentCode(string studentCode)
    {
        if (string.IsNullOrWhiteSpace(studentCode))
            throw new ArgumentException("Код студента пустой.", nameof(studentCode));

        string digits = OnlyDigits(studentCode);

        if (string.IsNullOrWhiteSpace(digits))
            throw new ArgumentException("В коде нет цифр.", nameof(studentCode));

        digits = digits.PadLeft(4, '0');

        string last4 = digits[^4..];
        string last2Text = last4[^2..];
        int last2 = int.Parse(last2Text);
        int sum = digits.Sum(c => c - '0');
        int seed = int.Parse(last4);

        return new VariantInfo
        {
            OriginalCode = studentCode,
            DigitsOnly = digits,
            Last4 = last4,
            Last2Text = last2Text,
            Last2 = last2,
            Sum = sum,
            Seed = seed
        };
    }

    private static string OnlyDigits(string value)
    {
        var sb = new StringBuilder();

        foreach (char ch in value)
        {
            if (char.IsDigit(ch))
                sb.Append(ch);
        }

        return sb.ToString();
    }
}