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
            //for (; ; )
            //{
            //     var message1 = "aaaaaaaaaaaaaaaaaaaaaaaa".GetBytes();
            //    var DES3key1 = BytesFromString("000100110011010001010111011110011001101110111100110111111111000110011010100100110010100100101010010101010010101010101010100100101001001010100100101010100101010100101010010101010010100100100010");
            //    var keys = Asymmetric.GenerateRSAKeys();

            //    var encrypted1 = Asymmetric.EncryptRSA(keys.Public, message1);
            //    var recovered = Asymmetric.DecryptRSA(keys.Private, encrypted1);

            //    Console.WriteLine(recovered.GetString());

            //    Console.ReadKey();
            //}

            //var message = BytesFromString("0000000100100011010001010110011110001001101010111100110111101111");
            //var message = BytesFromString("1000000011000100101000101110011010010001110101011011001111110111");

            Output.SetFileOutPut("OutputFile.txt");
            Console.WriteLine("Blaaaah");

            var message = "Hello";
            var hash = message.GetHash(HashTypes.SHALE);

            var aliceRSAKey = Asymmetric.GenerateRSAKeys();
            var bobRSAKey = Asymmetric.GenerateRSAKeys();

            var signature = Asymmetric.EncryptRSA(aliceRSAKey.Private, hash);


            //var message = "A";
            var DES3key = Symmetric.Generate3DESKey();
            //var key1 = BytesFromString("");
            
            var encrypted = Symmetric.Encrypt3DES(DES3key, message.GetBytes());

            var DES3KeyEncrypted = Asymmetric.EncryptRSA(bobRSAKey.Public, DES3key);

            var combinedMessage = CombineMessage(DES3KeyEncrypted, encrypted, signature);

            /** 
             * 
             * Simulate sending
             * 
             * **/

            var recoveredKey = new byte[35];
            var recoveredSignature = new byte[5];
            var recoveredCiphertext = new byte[combinedMessage.Length - recoveredKey.Length - recoveredSignature.Length];
            SplitMessage(ref recoveredKey, ref recoveredCiphertext, ref recoveredSignature, ref combinedMessage);

            var DES3Decrypted = Asymmetric.DecryptRSA(bobRSAKey.Private, recoveredKey);

            var decrypted = Symmetric.Decrypt3DES(DES3Decrypted, recoveredCiphertext).GetString();
            var recoveredHash = Asymmetric.DecryptRSA(aliceRSAKey.Public, recoveredSignature);
            var decryptedHash = decrypted.GetHash(HashTypes.SHALE);

            //This doesnt work, fix this.
            if (recoveredHash != decryptedHash)
            {
                
            }

            Output.Dispose();
        }

        static byte[] CombineMessage(byte[] symmetricKey, byte[] ciphertext, byte[] signature)
        {
            var block = new byte[symmetricKey.Length + ciphertext.Length + signature.Length];
            Buffer.BlockCopy(symmetricKey, 0, block, 0, symmetricKey.Length);
            Buffer.BlockCopy(ciphertext, 0, block, symmetricKey.Length, ciphertext.Length);
            Buffer.BlockCopy(signature, 0, block, symmetricKey.Length + ciphertext.Length, signature.Length);

            return block;
        }

        static void SplitMessage(ref byte[] symmetricKey, ref byte[] ciphertext, ref byte[] signature, ref byte[] message)
        {
            symmetricKey = new byte[35];
            signature = new byte[5];
            ciphertext = new byte[message.Length - symmetricKey.Length - signature.Length];

            Buffer.BlockCopy(message, 0, symmetricKey, 0, symmetricKey.Length);
            Buffer.BlockCopy(message, symmetricKey.Length, ciphertext, 0, ciphertext.Length);
            Buffer.BlockCopy(message, symmetricKey.Length + ciphertext.Length, signature, 0, signature.Length);
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
