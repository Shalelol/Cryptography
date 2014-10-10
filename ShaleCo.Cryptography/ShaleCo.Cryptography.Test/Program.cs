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
            var key = new byte[] { 0x02, 0x12, 0x54, 0x23, 0x02, 0x12, 0x54, 0x23 };

            Symmetric.EncryptAES(key, message);
        }
    }
}
