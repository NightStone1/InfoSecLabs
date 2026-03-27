namespace InfoSec.Common.Utils;

public static class HexUtils
{
    public static string ToHex(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        return Convert.ToHexString(data).ToLowerInvariant();
    }

    public static byte[] FromHex(string hex)
    {
        if (string.IsNullOrWhiteSpace(hex))
            throw new ArgumentException("Hex-строка пустая.", nameof(hex));

        return Convert.FromHexString(hex);
    }
}