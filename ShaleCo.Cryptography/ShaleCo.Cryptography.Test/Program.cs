using ShaleCo.Cryptography.Utils;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
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
                case "-race":
                    if(args.Length < 2)
                    {
                        Console.WriteLine("Please provide a message. -race \"example\"");
                        return;
                    }
                    CompareSpeeds(args[1]);
                    break;
                case "-deskey":
                    Console.WriteLine("DES Key. 64 Bit. 8 Bytes. 56 effiective bits.");
                    WriteByteArray(Symmetric.GenerateDESKey());
                    return;
                case "-des3key":
                    Console.WriteLine("DES3 Key. 192 Bit. 24 Bytes. 168 effiective bits.");
                    WriteByteArray(Symmetric.Generate3DESKey());
                    return;
                case "-des3encrypt":
                    if(args.Length != 3)
                    {
                        Console.WriteLine("Please provide a key in ASCII and a message.");
                        Console.WriteLine("-des3encrypt \"abcdefghijklmnopqrstuvwx\" \"Hello World.\"");
                        return;
                    }
                    var des3EncryptKey = args[1].GetBytes();
                    if (des3EncryptKey.Length != 24)
                    {
                        Console.WriteLine("Key was not the correct size: 192 bits.");
                        return;
                    }

                    Console.WriteLine("Your encrypted message:");
                    WriteByteArray(Symmetric.Encrypt3DES(des3EncryptKey, args[2].GetBytes()));
                    return;
                case "-desencrypt":
                    if(args.Length != 3)
                    {
                        Console.WriteLine("Please provide a key in ASCII and a message.");
                        Console.WriteLine("-desencrypt \"abcdefgh\" \"Hello World.\"");
                        return;
                    }
                    var desEncryptKey = args[1].GetBytes();
                    if (desEncryptKey.Length != 8)
                    {
                        Console.WriteLine("Key was not the correct size: 64 bits.");
                        return;
                    }

                    Console.WriteLine("Your encrypted message:");
                    WriteByteArray(Symmetric.EncryptDES(desEncryptKey, args[2].GetBytes()));
                    return;
                case "-des3decrypt":
                    if(args.Length != 3)
                    {
                        Console.WriteLine("Please provide a key in ASCII and a message.");
                        Console.WriteLine("-des3decrypt \"abcdefghijklmnopqrstuvwx\" \"Hello World.\"");
                        return;
                    }
                    var des3DecryptKey = args[1].GetBytes();
                    if (des3DecryptKey.Length != 24)
                    {
                        Console.WriteLine("Key was not the correct size: 192 bits.");
                        return;
                    }
                    var des3DecryptCipherText = args[2].GetBytes();
                    if(des3DecryptCipherText.Length % 8 != 0)
                    {
                        Console.WriteLine("ERROR: ciphertext is not the correct size. must be a multiple of 64 bits.");
                        return;
                    }

                    Console.WriteLine("Your decrypted message:");
                    WriteByteArray(Symmetric.Decrypt3DES(des3DecryptKey, des3DecryptCipherText));
                    return;
                case "-desdecrypt":
                    if (args.Length != 3)
                    {
                        Console.WriteLine("Please provide a key in ASCII and a message.");
                        Console.WriteLine("-desdecrypt \"abcdefgh\" \"Hello World.\"");
                        return;
                    }
                    var desDecryptKey = args[1].GetBytes();
                    if (desDecryptKey.Length != 8)
                    {
                        Console.WriteLine("Key was not the correct size: 64 bits.");
                        return;
                    }
                    var desDecryptCipherText = args[2].GetBytes();
                    if (desDecryptCipherText.Length % 8 != 0)
                    {
                        Console.WriteLine("ERROR: ciphertext is not the correct size. must be a multiple of 64 bits.");
                        return;
                    }

                    Console.WriteLine("Your decrypted message:");
                    WriteByteArray(Symmetric.DecryptDES(desDecryptKey, desDecryptCipherText));
                    return;
                case "-rsakey":
                    Console.WriteLine("RSA Key Pair");
                    Console.WriteLine(Asymmetric.GenerateRSAKeys());
                    return;
                case "-rsaencrypt":
                    if(args.Length != 3)
                    {
                        Console.WriteLine("Please provide a key pair in decimal and a message in ASCCI.");
                        Console.WriteLine("-rsaencrypt 373757,198399184603 \"Hello World.\"");
                        return;
                    }

                    var keys = args[1].Split(',');

                    if(keys.Length != 2)
                    {
                        Console.WriteLine("Invalid key, please provide a key pair in decimal");
                        Console.WriteLine("-rsaencrypt 373757,198399184603 \"Hello World.\"");
                        return;
                    }

                    BigInteger key1;
                    BigInteger key2;

                    if (!BigInteger.TryParse(keys[0], out key1))
                    {
                        Console.WriteLine("Invalid key, please provide a key pair in decimal");
                        Console.WriteLine("-rsaencrypt 373757,198399184603 \"Hello World.\"");
                        return;
                    }

                    if (!BigInteger.TryParse(keys[1], out key2))
                    {
                        Console.WriteLine("Invalid key, please provide a key pair in decimal");
                        Console.WriteLine("-rsaencrypt 373757,198399184603 \"Hello World.\"");
                        return;
                    }

                    var message = args[2].GetBytes();

                    var cipherText = Asymmetric.EncryptRSA(new RSAKey(key1.ToByteArray(), key2.ToByteArray()), message);
                    Console.WriteLine("Your encrypted message");
                    WriteByteArray(cipherText);
                    return;
                case "-rsadecrypt":
                    if(args.Length != 3)
                    {
                        Console.WriteLine("Please provide a key pair in decimal and a message in ASCCI.");
                        Console.WriteLine("-rsadecrypt 373757,198399184603 \"Hello World.\"");
                        return;
                    }

                    var decryptkeys = args[1].Split(',');

                    if (decryptkeys.Length != 2)
                    {
                        Console.WriteLine("Invalid key, please provide a key pair in decimal");
                        Console.WriteLine("-rsadecrypt 373757,198399184603 \"Hello World.\"");
                        return;
                    }

                    BigInteger decryptKey1;
                    BigInteger decryptKey2;

                    if (!BigInteger.TryParse(decryptkeys[0], out decryptKey1))
                    {
                        Console.WriteLine("Invalid key, please provide a key pair in decimal");
                        Console.WriteLine("-rsadecrypt 373757,198399184603 \"Hello World.\"");
                        return;
                    }

                    if (!BigInteger.TryParse(decryptkeys[1], out decryptKey2))
                    {
                        Console.WriteLine("Invalid key, please provide a key pair in decimal");
                        Console.WriteLine("-rsadecrypt 373757,198399184603 \"Hello World.\"");
                        return;
                    }

                    var decryptMessage = args[2].GetBytes();

                    var decryuptCipherText = Asymmetric.EncryptRSA(new RSAKey(decryptKey1.ToByteArray(), decryptKey2.ToByteArray()), decryptMessage);
                    Console.WriteLine("Your decrypted message");
                    WriteByteArray(decryuptCipherText);
                    return;
                case "-hash":
                    if(args.Length != 2)
                    {
                        Console.WriteLine("Please enter a value in ASCII to hash");
                        return;
                    }
                    
                    Console.WriteLine("Custom hash.");
                    WriteByteArray(args[1].GetHash(HashTypes.SHALE));
                    return;
#if DEBUG
                case "-scenariodebug":
                    RunBasicScenarioDebug("Hello World. Foo Bar. !@#$%^&*");
                    return;
#endif
                default:
                    WriteHelp();
                    return;
            }
        }

        static void ComparisonTest()
        {
            var filePath = Directory.GetCurrentDirectory() + "/test.csv";
            var lines = new List<string>();
            var message = "AAAAAAAA";

            var timer = new Stopwatch();

            lines.Add("Characters,DES3,RSA");

            for(var j = 0; j < 100; j++)
            {
                timer.Start();
                for (var i = 0; i < 100; i++)
                {
                    var symmetricKey = Symmetric.Generate3DESKey();
                    var encrypted = Symmetric.Encrypt3DES(symmetricKey, message.GetBytes());
                    var decrypted = Symmetric.Decrypt3DES(symmetricKey, encrypted);
                    if (decrypted.GetString() != message)
                    {
                        Console.WriteLine("ERROR: Encryption Failed");
                        return;
                    }
                }
                timer.Stop();

                var symmetricTime = timer.ElapsedMilliseconds;

                timer.Reset();

                timer.Start();
                for (var i = 0; i < 100; i++)
                {
                    var asymetricKey = Asymmetric.GenerateRSAKeys();
                    var encrypted = Asymmetric.EncryptRSA(asymetricKey.Public, message.GetBytes());
                    var decrypted = Asymmetric.DecryptRSA(asymetricKey.Private, encrypted);
                    if (decrypted.GetString() != message)
                    {
                        Console.WriteLine("ERROR: Encryption Failed");
                        return;
                    }
                }
                timer.Stop();

                var asymetricTime = timer.ElapsedMilliseconds;

                lines.Add(string.Format("{0},{1},{2}", message.Length, symmetricTime, asymetricTime));
                message += "AAAAAAAA";
            }

            File.WriteAllLines(filePath, lines);
        }

        static void WriteHelp()
        {
            Console.WriteLine("Run the assignment scenario:");
            Console.WriteLine("-scenario \"Message\"");
            Console.WriteLine("-scenario \"Message\" -fileoutput");
            Console.WriteLine("-scenario \"Message\" -fileoutput \"C:/output.txt\"");
            Console.WriteLine("");
            Console.WriteLine("Race DES3 and RSA in the encryption of a message");
            Console.WriteLine("-race \"Message\"");
            Console.WriteLine("");
            Console.WriteLine("Generate encryption keys");
            Console.WriteLine("-deskey");
            Console.WriteLine("-des3key");
            Console.WriteLine("-rsakey");
            Console.WriteLine("");
            Console.WriteLine("Encrypt an ASCII message using an ASCII key with DES3");
            Console.WriteLine("-des3encrypt \"abcdefghijklmnopqrstuvwx\" \"Hello World.\"");
            Console.WriteLine("");
            Console.WriteLine("Encrypt an ASCII message using an ASCII key with DES");
            Console.WriteLine("-desencrypt \"abcdefgh\" \"Hello World.\"");
            Console.WriteLine("");
            Console.WriteLine("Decrypt an ASCII message using an ASCII key with DES3");
            Console.WriteLine("-des3decrypt \"abcdefghijklmnopqrstuvwx\" \"Hello World.\"");
            Console.WriteLine("");
            Console.WriteLine("Decrypt an ASCII message using an ASCII key with DES");
            Console.WriteLine("-desdecrypt \"abcdefgh\" \"Hello World.\"");
            Console.WriteLine("");
            Console.WriteLine("Encrypt an ASCII message using an decimal key pair with RSA");
            Console.WriteLine("-rsaencrypt 373757,198399184603 \"Hello World.\"");
            Console.WriteLine("");
            Console.WriteLine("Decrypt an ASCII message using an decimal key pair with RSA");
            Console.WriteLine("-rsadecrypt 373757,198399184603 \"Hello World.\"");
            Console.WriteLine("");
            Console.WriteLine("Generate a hash for any ASCII message using my special hashing algorithm.");
            Console.WriteLine("-hash \"Message\"");
        }

        static void CompareSpeeds(string message)
        {
            var timer = new Stopwatch();

            var messageBytes = message.GetBytes();
            var symmetricKey = Symmetric.Generate3DESKey();
            var asymetricKey = Asymmetric.GenerateRSAKeys();
            
            timer.Start();
            for(var i = 0; i < 100; i++)
            {
                var encrypted = Symmetric.Encrypt3DES(symmetricKey, messageBytes);
                var decrypted = Symmetric.Decrypt3DES(symmetricKey, encrypted);
                if(decrypted.GetString() != message)
                {
                    Console.WriteLine("ERROR: Encryption Failed");
                    return;
                }
            }
            timer.Stop();

            var symmetricTime = timer.ElapsedMilliseconds;

            timer.Reset();

            timer.Start();
            for(var i = 0; i < 100; i++)
            {
                var encrypted = Asymmetric.EncryptRSA(asymetricKey.Public, messageBytes);
                var decrypted = Asymmetric.DecryptRSA(asymetricKey.Private, encrypted);
                if(decrypted.GetString() != message)
                {
                    Console.WriteLine("ERROR: Encryption Failed");
                    return;
                }
            }
            timer.Stop();

            var asymetricTime = timer.ElapsedMilliseconds;

            Console.WriteLine("Symmetric Encryption took {0} ms to encrypt and decrypt 100 times", symmetricTime);
            Console.WriteLine("Asymmetric Encryption took {0} ms to encrypt and decrypt 100 times", asymetricTime);

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
            for (var i = 0; i < 20; i++)
            {
                Console.Write("-");
                Thread.Sleep(100);
            }
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

        static void RunBasicScenarioDebug(string message)
        {
            var messageBytes = message.GetBytes();

            var hash = message.GetHash(HashTypes.SHALE);

            var aliceKeys = Asymmetric.GenerateRSAKeys();
            var bobKeys = Asymmetric.GenerateRSAKeys();

            var encryptedHash = Asymmetric.EncryptRSA(aliceKeys.Private, hash);

            var augmentedMessage = Helper.CombineByteArrays(messageBytes, encryptedHash);

            var DES3Key = Symmetric.Generate3DESKey();

            var encryptedMessage = Symmetric.Encrypt3DES(DES3Key, augmentedMessage);

            var encryptedKey = Asymmetric.EncryptRSA(bobKeys.Public, DES3Key);

            var transmissionMessage = Helper.CombineByteArrays(encryptedMessage, encryptedKey);

            var recoveredEncryptedKey = new byte[30];
            var recoveredCipherText = new byte[transmissionMessage.Length - recoveredEncryptedKey.Length];
            SplitMessage(ref recoveredEncryptedKey, ref recoveredCipherText, transmissionMessage);

            var decrypedDES3Key = Asymmetric.DecryptRSA(bobKeys.Private, recoveredEncryptedKey);

            var decryptedMessage = Symmetric.Decrypt3DES(decrypedDES3Key, recoveredCipherText);

            var recoveredSignature = new byte[5];
            var recoveredMessage = new byte[decryptedMessage.Length - recoveredSignature.Length];
            SplitMessage(ref recoveredSignature, ref recoveredMessage, decryptedMessage);

            var decryptedHash = Asymmetric.DecryptRSA(aliceKeys.Public, recoveredSignature);

            var recoveredMessageHash = recoveredMessage.GetString().GetHash(HashTypes.SHALE);

            if (decryptedHash.SequenceEqual(recoveredMessageHash))
            {
                Console.WriteLine("Hashes are identical");
                Console.WriteLine("This means we can be sure the message is from Alice and was unaltered");
            }
            else
            {
                Console.WriteLine("Hashes are different");
                Console.WriteLine("This means either the message was not from Alice, or it was altered during transmission");
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
