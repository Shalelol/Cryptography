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
            for (; ; )
            {
                var message = "This is a long test message which is being used to prove there are no errors.".GetBytes();
                var keys = Asymmetric.GenerateRSAKeys();

                var encrypted = Asymmetric.EncryptRSA(keys.Private, message);
                var recovered = Asymmetric.DecryptRSA(keys.Public, encrypted);

                Console.WriteLine(recovered.GetString());
                
                Console.ReadKey();
            }

            ////var message = BytesFromString("0000000100100011010001010110011110001001101010111100110111101111");
            ////var message = BytesFromString("1000000011000100101000101110011010010001110101011011001111110111");
            //var message = "A";
            //var hash = message.GetHash();
                        
            //var aliceRSAKey = Asymmetric.GenerateRSAKeys();
            //var bobRSAKey = Asymmetric.GenerateRSAKeys();

            //var signature = Asymmetric.RSA(aliceRSAKey.Private, hash);
            

            ////var message = "A";
            //var DES3key = BytesFromString("000100110011010001010111011110011001101110111100110111111111000100010011001101000101011101111001100110111011110011011111111100010001001100110100010101110111100110011011101111001101111111110001");
            ////var key1 = BytesFromString("0001001100110100010101110111100110011011101111001101111111110001");

            //var encrypted = Symmetric.Encrypt3DES(DES3key, message.GetBytes());

            //var DES3KeyEncrypted = Asymmetric.RSA(bobRSAKey.Public, DES3key);

            //var combinedMessage = CombineMessage(DES3KeyEncrypted, encrypted, signature);

            ///** 
            // * 
            // * Simulate sending
            // * 
            // * **/

            //var recoveredKey = new byte[24];
            //var recoveredSignature = new byte[4];
            //var recoveredCiphertext = new byte[combinedMessage.Length - recoveredKey.Length - recoveredSignature.Length];
            //SplitMessage(recoveredKey, recoveredCiphertext, recoveredSignature, combinedMessage);

            //var DES3Decrypted = Asymmetric.RSA(bobRSAKey.Private, recoveredKey);

            //var decrypted = Symmetric.Decrypt3DES(DES3Decrypted, recoveredCiphertext).GetString();
            //var recoveredHash = Asymmetric.RSA(aliceRSAKey.Public, recoveredSignature);
            //var decryptedHash = decrypted.GetHash();

            //if (recoveredHash != decryptedHash)
            //{
            //    throw new Exception("Message was either not from alice or it was altered");
            //}
        }

        static byte[] CombineMessage(byte[] symmetricKey, byte[] ciphertext, byte[] signature)
        {
            var block = new byte[symmetricKey.Length + ciphertext.Length + signature.Length];
            Buffer.BlockCopy(symmetricKey, 0, block, 0, symmetricKey.Length);
            Buffer.BlockCopy(ciphertext, 0, block, symmetricKey.Length, symmetricKey.Length);
            Buffer.BlockCopy(signature, 0, block, symmetricKey.Length + signature.Length, signature.Length);

            return block;
        }

        static void SplitMessage(byte[] symmetricKey, byte[] ciphertext, byte[] signature, byte[] message)
        {
            symmetricKey = new byte[24];
            signature = new byte[4];
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
