namespace Lab2;

internal static class VigenereCipher
{
    public static string Encrypt(string text, string key) => Transform(text, key, encrypt: true);

    public static string Decrypt(string text, string key) => Transform(text, key, encrypt: false);

    private static string Transform(string text, string key, bool encrypt)
    {
        var result = new char[text.Length];
        int keyIndex = 0;

        for (int i = 0; i < text.Length; i++)
        {
            char ch = text[i];

            if (ch is < 'A' or > 'Z')
            {
                result[i] = ch;
                continue;
            }

            int p = ch - 'A';
            int k = key[keyIndex % key.Length] - 'A';
            int c = encrypt ? (p + k) % 26 : (p - k + 26) % 26;

            result[i] = (char)('A' + c);
            keyIndex++;
        }

        return new string(result);
    }
}