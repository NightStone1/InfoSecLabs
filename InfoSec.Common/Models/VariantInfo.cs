namespace InfoSec.Common.Models;

public sealed class VariantInfo
{
    public string OriginalCode { get; init; } = string.Empty;
    public string DigitsOnly { get; init; } = string.Empty;
    public string Last4 { get; init; } = string.Empty;
    public string Last2Text { get; init; } = string.Empty;
    public int Last2 { get; init; }
    public int Sum { get; init; }
    public int Seed { get; init; }
}