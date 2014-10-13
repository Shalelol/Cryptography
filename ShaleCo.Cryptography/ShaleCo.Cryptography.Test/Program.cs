using ShaleCo.Cryptography.Utils;
using System;
using System.Collections;
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
            //var message = BytesFromString("0000000100100011010001010110011110001001101010111100110111101111");
            //var message = BytesFromString("1000000011000100101000101110011010010001110101011011001111110111");
            var message = "Hello world.".GetBytes();

            //var message = "A";
            var key = BytesFromString("0001001100110100010101110111100110011011101111001101111111110001");
            //var key = BytesFromString("1100100000101100111010101001111011011001001111011111101110001111");

            var encrypted = Symmetric.EncryptDES(key, message);
            var decrypted = Symmetric.DecryptDES(key, encrypted);
            var x = decrypted.GetString();
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
