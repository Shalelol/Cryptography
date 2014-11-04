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
            //Run through basic scenario
            //-scenario "Message text"

            //DES encrypt
            //-DES "Message" "Key"

            //-DESDecrypt "Message" "Key"

            //DES3 encrypt
            //-DES3 "Message" "Key"

            //-DES3Decrypt "Message" "Key"

            //RSA encrypt/decrypt
            //-RSA "Message" "Key"

            //Generate RSA key
            //-RSAKey

            //Get Hash
            //-Hash "Message" "HashType"

            //Options
            //-FileOutput "filePath"

            switch(args[0])
            {
                case "-scenario":
                    break;
                case "-DES":
                    try
                    {
                        if (args[2] != null)
                        {
                            var key = BytesFromString(args[2]);
                        }
                        else
                        {
                            var key = Symmetric
                        }
                        var message = args[1].GetBytes();
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.Message);
                    }
                    break;
                case "-DESDecrypt":
                    break;
                case "-DES3":
                    break;
                case "-DES3Decrypt":
                    break;
                case "-RSA":
                    break;
                case "-RSAKey":
                    break;
                case "-hash":
                    break;
                default:
                    break;
            }
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
