using ShaleCo.Cryptography.Utils;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading;
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

            if(args.Length < 1)
            {
                Console.WriteLine("ShaleCo.Cryptography v1.0.0.0");
                Console.WriteLine("Created by Shale Kuzmanovski 2014");
                return;
            }

            switch(args[0])
            {
                case "-scenario":
                    if(args.Length < 3)
                    {
                        if(args.Length < 2)
                        {
                            Console.WriteLine("Please enter a message to encrypt.");
                            return;
                        }

                        RunBasicScenario(args[1]);
                        return;
                    }
                    
                    if(args[2] == "-fileoutput")
                    {
                        if(args.Length < 4)
                        {
                            RunBasicScenario(args[1], true);
                            return;
                        }
                        else
                        {
                            RunBasicScenario(args[1], true, args[3]);
                            return;
                        }
                    }

                    Console.WriteLine("Unrecognised command. Try -help to see available commands.");
                    return;
                case "-DES":
                    var message = "BLAHBALBLAHasdasda".GetBytes();
                    var key = Symmetric.Generate3DESKey();
                    var encrypted = Symmetric.Encrypt3DES(key, message);
                    var recovered = Symmetric.Decrypt3DES(key, encrypted);
                    var recoveredText = recovered.GetString();
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

        static void RunBasicScenario(string message, bool fileOutput = false, string filePath = null)
        {
            if (fileOutput)
            {
                if (filePath == null)
                {
                    filePath = Directory.GetCurrentDirectory() + @"\BasicScenario.txt";
                }

                Output.SetFileOutPut(filePath);
            }

            var messageBytes = message.GetBytes();

            Console.WriteLine("Begining basic scenario with message");
            Console.WriteLine(message);
            WriteByteArray(messageBytes);
            WriteGap();

            var hash = message.GetHash(HashTypes.SHALE);

            Console.WriteLine("Hash computed");
            WriteByteArray(hash);
            WriteGap();

            var aliceKeys = Asymmetric.GenerateRSAKeys();
            var bobKeys = Asymmetric.GenerateRSAKeys();

            Console.WriteLine("RSA keys generated");
            Console.WriteLine("Alice: \n{0}", aliceKeys);
            Console.WriteLine("Bob: \n{0}", bobKeys);
            WriteGap();

            var encryptedHash = Asymmetric.EncryptRSA(aliceKeys.Private, hash);

            Console.WriteLine("Hash encrypted with Alice's private Key");
            WriteByteArray(encryptedHash);
            WriteGap();

            var augmentedMessage = Helper.CombineByteArrays(messageBytes, encryptedHash);

            Console.WriteLine("Combined original message and encrypted hash.");
            WriteByteArray(augmentedMessage);
            WriteGap();

            var DES3Key = Symmetric.Generate3DESKey();

            Console.WriteLine("DES3 Key Generated");
            WriteByteArray(DES3Key);
            WriteGap();

            var encryptedMessage = Symmetric.Encrypt3DES(DES3Key, augmentedMessage);

            Console.WriteLine("Combined message encrypted with DES3 encryption");
            WriteByteArray(encryptedMessage);
            WriteGap();

            var encryptedKey = Asymmetric.EncryptRSA(bobKeys.Public, DES3Key);

            Console.WriteLine("DES3 Encrypted with bob's public key");
            WriteByteArray(encryptedKey);
            WriteGap();

            var transmissionMessage = Helper.CombineByteArrays(encryptedMessage, encryptedKey);

            Console.WriteLine("Encrypted Message and encrypted session key combined for transmission");
            WriteByteArray(encryptedKey);
            WriteGap();

            /** --------------------------------------------------------------------------------------- **/

            Console.WriteLine("Simulating Transmission");
            Console.Write("[");
            Console.CursorLeft = 21;
            Console.Write("]");
            Console.CursorLeft = 1;
            //for (var i = 0; i < 20; i++)
            //{
            //    Console.Write("-");
            //    Thread.Sleep(300);
            //}
            WriteGap();

            /** --------------------------------------------------------------------------------------- **/

            var recoveredEncryptedKey = new byte[30];
            var recoveredCipherText = new byte[transmissionMessage.Length - recoveredEncryptedKey.Length];
            SplitMessage(ref recoveredEncryptedKey, ref recoveredCipherText, transmissionMessage);

            Console.WriteLine("Split transmission message into key and ciphertext\n");
            Console.WriteLine("Key");
            WriteByteArray(recoveredEncryptedKey);
            Console.WriteLine();
            Console.WriteLine("Ciphertext");
            WriteByteArray(recoveredCipherText);
            WriteGap();

            var decrypedDES3Key = Asymmetric.DecryptRSA(bobKeys.Private, recoveredEncryptedKey);

            Console.WriteLine("Decrypted DES3 key using bob's private key");
            WriteByteArray(decrypedDES3Key);
            WriteGap();

            var decryptedMessage = Symmetric.Decrypt3DES(decrypedDES3Key, recoveredCipherText);

            Console.WriteLine("Decrypted ciphertext using decrypted DES3 Key");
            WriteByteArray(decryptedMessage);
            WriteGap();

            var recoveredSignature = new byte[5];
            var recoveredMessage = new byte[decryptedMessage.Length - recoveredSignature.Length];
            SplitMessage(ref recoveredSignature, ref recoveredMessage, decryptedMessage);

            Console.WriteLine("Split ciphertext into message and signature\n");
            Console.WriteLine("Message");
            WriteByteArray(recoveredMessage);
            Console.WriteLine();
            Console.WriteLine("signature");
            WriteByteArray(recoveredSignature);
            WriteGap();

            var decryptedHash = Asymmetric.DecryptRSA(aliceKeys.Public, recoveredSignature);

            Console.WriteLine("Signature decrypted uusing alice's public key");
            WriteByteArray(decryptedHash);
            WriteGap();

            var recoveredMessageHash = recoveredMessage.GetString().GetHash(HashTypes.SHALE);

            Console.WriteLine("Compare two hashes\n");
            Console.WriteLine("Generated by sender");
            WriteByteArray(decryptedHash);
            Console.WriteLine();
            Console.WriteLine("Generated by reciever");
            WriteByteArray(recoveredMessageHash);
            WriteGap();

            if(decryptedHash.SequenceEqual(recoveredMessageHash))
            {
                Console.WriteLine("Hashes are identical");
                Console.WriteLine("This means we can be sure the message is from Alice and was unaltered");
            }
            else
            {
                Console.WriteLine("Hashes are different");
                Console.WriteLine("This means either the message was not from Alice, or it was altered during transmission");
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

        static void SplitMessage(ref byte[] part1, ref byte[] part2, byte[] message)
        {
            Buffer.BlockCopy(message, 0, part2, 0, part2.Length);
            Buffer.BlockCopy(message, part2.Length, part1, 0, part1.Length);
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

        static void WriteByteArray(byte[] bytes)
        {
            Console.WriteLine("Binary: {0}", Helper.ByteArrayToDecimalString(bytes));
            Console.WriteLine("Hex: {0}", Helper.ByteArrayToHexString(bytes));
            Console.WriteLine("Decimal: {0}", new BigInteger(bytes).ToString());
            Console.WriteLine("ASCII: {0}", bytes.GetString());
        }

        static void WriteGap()
        {
            Console.WriteLine();
            Console.WriteLine("----------");
            Console.WriteLine();
        }
    }
}
