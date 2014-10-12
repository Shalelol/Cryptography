using ShaleCo.Cryptography.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ShaleCo.Cryptography.Test
{
    class Program
    {
        static void Main(string[] args)
        {
            var message = "#Eg����";
            var key = BytesFromString("1100100000101100111010101001111011011001001111011111101110001111");

            var encrypted = Symmetric.EncryptDES(key, message);
            var decrypted = Symmetric.DecryptDES(key, encrypted);
        }

        static byte[] BytesFromString(string input)
        {
            var numBytes = input.Length / 8;
            byte[] bytes = new byte[numBytes];
            for(var i = 0; i < numBytes; i++)
            {
                bytes[i] = Convert.ToByte(input.Substring(8 * i, 8), 2);
            }

            return bytes;
        }
    }
}
