namespace InfoSec.Common.Utils;

public static class TextUtils
{
    public static string FitToLength(string value, int length, char padChar = '_')
    {
        if (value is null) throw new ArgumentNullException(nameof(value));
        if (length < 0) throw new ArgumentOutOfRangeException(nameof(length));

        if (value.Length > length)
            return value[..length];

        if (value.Length < length)
            return value.PadRight(length, padChar);

        return value;
    }
}