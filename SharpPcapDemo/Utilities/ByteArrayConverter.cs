using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpPcapDemo.Utilities
{
    public class ByteArrayConverter
    {
        public int ByteArrayToInt(byte[] byteArray)
        {
            if (byteArray == null)
            {
                throw new ArgumentNullException(nameof(byteArray), "Byte array cannot be null.");
            }

            // Ensure the byte array is in the correct endianness (if needed)
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(byteArray);
            }

            return BitConverter.ToInt32(byteArray, 0);
        }
    }
}
