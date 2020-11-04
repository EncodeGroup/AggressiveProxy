using System;
using System.Globalization;
using System.Text;

namespace LetMeOutSharp
{
    public static class Utilities
    {
        //Am I a 64 or 32-bit process?
        public static string Is64BitProcess
        {
            get { return IntPtr.Size == 8 ? "1" : "0"; }
        }

        public static Uri ToUri(this string str)
        {
            Uri url = new System.Net.WebProxy(str).Address;
            return url;
        }

        public static string ToBase64(this string str)
        {
            return Convert.ToBase64String(Encoding.ASCII.GetBytes(str));
        }

        public static byte[] ConvertHexStringToByteArray(this string hexString)
        {
            if (hexString.Length % 2 != 0)
            {
                throw new ArgumentException(String.Format(CultureInfo.InvariantCulture,
                    "The binary key cannot have an odd number of digits: {0}", hexString));
            }

            byte[] data = new byte[hexString.Length / 2];
            for (int index = 0; index < data.Length; index++)
            {
                string byteValue = hexString.Substring(index * 2, 2);
                data[index] = Byte.Parse(byteValue, NumberStyles.HexNumber,
                    CultureInfo.InvariantCulture);
            }

            return data;
        }
    }
}
