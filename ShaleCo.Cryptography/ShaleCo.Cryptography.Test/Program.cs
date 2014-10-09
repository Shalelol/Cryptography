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
            var message = "This is a sample message".GetHash(HashTypes.DEFAULT);

            var keys = Asymmetric.GenerateRSAKeys();

            var encrypted = Asymmetric.RSA(keys.Private, message);
            var recovered = Asymmetric.RSA(keys.Public, encrypted);


            Console.ReadKey();

        }
    }
}
