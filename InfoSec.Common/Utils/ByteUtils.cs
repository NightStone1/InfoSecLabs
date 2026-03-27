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

    public static byte[] Concat(params byte[][] arrays)
    {
        if (arrays is null) throw new ArgumentNullException(nameof(arrays));

        int totalLength = arrays.Sum(a => a?.Length ?? 0);
        byte[] result = new byte[totalLength];

        int offset = 0;
        foreach (byte[]? arr in arrays)
        {
            if (arr is null) continue;
            Buffer.BlockCopy(arr, 0, result, offset, arr.Length);
            offset += arr.Length;
        }

        return result;
    }

    public static byte[] FlipByte(byte[] data, int index)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (index < 0 || index >= data.Length) throw new ArgumentOutOfRangeException(nameof(index));

        byte[] copy = (byte[])data.Clone();
        copy[index] ^= 0x01;
        return copy;
    }
}