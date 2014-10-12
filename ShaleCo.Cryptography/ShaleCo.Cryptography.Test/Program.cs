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
            var message = "Hello world.";
            var key = new byte[] { 0xf1, 0xdf, 0xbc, 0x9b, 0x79, 0x57, 0x34, 0x13 };

            var encrypted = Symmetric.EncryptDES(key, message);
            var decrypted = Symmetric.DecryptDES(key, encrypted);
        }
    }
}
