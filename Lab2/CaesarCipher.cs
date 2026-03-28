namespace Lab2;

internal static class CaesarCipher
{
    public static string Encrypt(string text, int shift) => Transform(text, shift);

    public static string Decrypt(string text, int shift) => Transform(text, -shift);

    private static string Transform(string text, int shift)
    {
        char ShiftChar(char ch)
        {
            if (ch is < 'A' or > 'Z')
                return ch;

            int x = ch - 'A';
            int y = (x + shift) % 26;
            if (y < 0) y += 26;

            return (char)('A' + y);
        }

        return new string(text.Select(ShiftChar).ToArray());
    }
}