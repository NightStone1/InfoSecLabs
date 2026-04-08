namespace InfoSec.Common.Utils;

public static class ByteUtils
{
    public static byte[] Xor(byte[] left, byte[] right)
    {
        if (left is null) throw new ArgumentNullException(nameof(left));
        if (right is null) throw new ArgumentNullException(nameof(right));
        if (left.Length != right.Length)
            throw new ArgumentException("Массивы должны быть одинаковой длины.");

        byte[] result = new byte[left.Length];

        for (int i = 0; i < left.Length; i++)
            result[i] = (byte)(left[i] ^ right[i]);

        return result;
    }    
}