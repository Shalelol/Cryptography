﻿using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ShaleCo.Cryptography.Utils;

namespace ShaleCo.Cryptography
{
    public static class Symmetric
    {
        private static List<int> _subKeyGenPC1;
        private static List<int> _subKeyGenPC2;
        private static List<int> _subKeyGenLeftShift;
        private static List<int> _encryptionIP;
        private static List<int> _encryptionIPInverse;
        private static List<int> _encryptionEBit;
        private static List<int> _encryptionP;

        private static SBoxes _sBoxes;

        static Symmetric()
        {
            _subKeyGenPC1 = Helper.LoadFile<int>("/Resources/DES-SubKey-Generation-pc1.csv");
            _subKeyGenPC2 = Helper.LoadFile<int>("/Resources/DES-SubKey-Generation-pc2.csv");
            _subKeyGenLeftShift = Helper.LoadFile<int>("/Resources/DES-SubKey-Generation-leftshift.csv");
            _encryptionIP = Helper.LoadFile<int>("/Resources/DES-Encryption-IP.csv");
            _encryptionIPInverse = Helper.LoadFile<int>("/Resources/DES-Encryption-IPInverse.csv");
            _encryptionEBit = Helper.LoadFile<int>("/Resources/DES-Encryption-EBit-Table.csv");
            _encryptionP = Helper.LoadFile<int>("/Resources/DES-Encryption-P.csv");

            _sBoxes = new SBoxes("/Resources/DES-Encryption-SBoxes.csv");
        }

        public static byte[] EncryptDES(byte[] key, byte[] message)
        {
            //Chang this back to accepting a string
            var paddedMessage = Padding(message);

            var blocks = BreakIntoBlocks(paddedMessage, 64);
            var keys = GenerateSubKeys(key);

            return DES(keys, blocks);
        }

        public static byte[] DecryptDES(byte[] key, byte[] cipher)
        {
            var blocks = BreakIntoBlocks(cipher, 64);
            var keys = GenerateSubKeys(key);
            keys.Reverse();

            var decrypted = DES(keys, blocks);

            decrypted = ReversePadding(decrypted);

            return decrypted;
        }

        public static byte[] DES(List<BitArray> keys, List<BitArray> blocks)
        {
            foreach(var block in blocks)
            {
                block.Log("M", 4);
                var initialPermutation = new BitArray(64);
                var left = new BitArray(32);
                var right = new BitArray(32);

                //Rearange bits according to IP (Initial permutation)
                PBox(initialPermutation, block, _encryptionIP);

                initialPermutation.Log("IP", 4);

                //Split bits into left and right 32 bit halves
                Split(initialPermutation, left, right);

                //Run through 16 rounds
                for (var i = 0; i < 16; i++)
                {
                    var oldLeft = left.Clone() as BitArray;
                    var oldRight = right.Clone() as BitArray;
                    var expanded = new BitArray(48);

                    //Expand right half according he the expansion box
                    PBox(expanded, oldRight, _encryptionEBit);

                    //XOR expanded block with 48 bit key
                    expanded = expanded.Xor(keys[i]);

                    var substituted = new List<bool>();

                    //Substitute expanded 48 block with 8 SBoxes to get back to 32 bits
                    SBox(substituted, expanded);

                    var subBitArray = new BitArray(substituted.ToArray());

                    subBitArray.Log("SBox:", 4);

                    //Put the substituted values back into right using a Permutation Box
                    PBox(right, subBitArray, _encryptionP);
                    right = right.Xor(oldLeft);
                    
                    left = oldRight;

                    right.Log("R" + i, 4);
                    left.Log("L" + i, 4);
                }

                //Swap left and right
                for(var i = 0; i < 32; i++)
                {
                    initialPermutation[i] = right[i];
                    initialPermutation[i + 32] = left[i];
                }

                initialPermutation.Log("R16L16", 8);

                //Apply final Permutation;
                PBox(block, initialPermutation, _encryptionIPInverse);

                block.Log("IP-1", 8);
            }

            return CombineBlocks(blocks);
        }

        private static void SBox(List<bool> target, BitArray source)
        {
            for (var j = 0; j < 8; j++)
            {
                var index = j * 6;
                var rowNumber = Helper.Base2(source[index], source[index + 5]);
                var columnNumber = Helper.Base4(source[index + 1], source[index + 2], source[index + 3], source[index + 4]);

                var value = _sBoxes.Boxes.ElementAt(j).Rows.ElementAt(rowNumber).ElementAt(columnNumber);

                var valueBits = new BitArray(BitConverter.GetBytes(value));

                //Reduce back to 32 bit using the 8 SBoxes
                for (var k = 0; k < 4; k++)
                {
                    target.Add(valueBits[k]);
                }
            }
        }

        private static void PBox(BitArray target, BitArray source, List<int> pBox)
        {
            for (var i = 0; i < pBox.Count; i++)
            {
                target[i] = source[pBox[i] - 1];
            }
        }

        private static void Split(BitArray source, BitArray left, BitArray right)
        {
            if (left.Count != source.Count / 2 || right.Count != source.Count / 2)
            {
                throw new Exception("BitArrays are not valid sizes");
            }

            for (var i = 0; i < source.Count / 2; i++)
            {
                left[i] = source[i];
                right[i] = source[i + source.Count / 2];
            }
        }

        /// <summary>
        /// Padding is done usng PKSC7 padding.
        /// </summary>
        private static byte[] Padding(byte[] message)
        {
            int remainder;
            if(message.Length > 8)
            {
                remainder = message.Length % 8;
            }
            else
            {
                remainder = 8 - message.Length;
            }

            var padding = BitConverter.GetBytes(remainder)[0];
            var paddingList = new List<byte>();

            for(var i = 0; i < remainder; i++)
            {
                paddingList.Add(padding);
            }

            byte[] paddedBytes;
            var paddingArray = paddingList.ToArray();


            using (MemoryStream stream = new MemoryStream())
            {
                stream.Write(message, 0, message.Length);
                stream.Write(paddingArray, 0, paddingArray.Length);

                paddedBytes = stream.ToArray();
            }

            return paddedBytes;
        }
        private static byte[] ReversePadding(byte[] bytes)
        {
            int paddingNumber = bytes[bytes.Length - 1];

            if(paddingNumber > 7)
            {
                return bytes;
            }

            for(var i = 1; i <= paddingNumber; i++)
            {
                if(bytes[bytes.Length - i] != paddingNumber)
                {
                    return bytes;
                }
            }

            var newArray = bytes.Take(bytes.Length - paddingNumber).ToArray();

            return newArray;
        }
        private static List<BitArray> GenerateSubKeys(byte[] key)
        {
            var k = new BitArray(key);
            var k1 = new BitArray(56);

            //Create K1 using PC-1 to re-arrange the key's bits
            PBox(k1, k, _subKeyGenPC1);

            var c = new List<BitArray>();
            var d = new List<BitArray>();
            var kList = new List<BitArray>();
            var cd = new List<BitArray>();

            for (var i = 0; i < 17; i++)
            {
                c.Add(new BitArray(28));
                d.Add(new BitArray(28));
                cd.Add(new BitArray(56));
                kList.Add(new BitArray(48));
            }

            //Split K1 into two sub keys C and D
            Split(k1, c[0], d[0]);

            Console.WriteLine();
            //Form series of C and D keys by left shifting
            for (var i = 1; i < 17; i++)
            {
                c[i] = c[i - 1].LeftShift(_subKeyGenLeftShift[i-1]);
                d[i] = d[i - 1].LeftShift(_subKeyGenLeftShift[i-1]);

                for(var j = 0; j < 28; j++)
                {
                    cd[i][j] = c[i][j];
                    cd[i][j + 28] = d[i][j];
                }
            }

            //Create set of Keys using PC-2 to re-arrange the key's bits from CD
            for (var i = 1; i < 17; i++)
            {
                for(var j = 0; j < 48; j++)
                {
                    PBox(kList[i], cd[i], _subKeyGenPC2);
                }
            }

            kList.RemoveAt(0);

            return kList;
        }
        private static List<BitArray> BreakIntoBlocks(byte[] message, int blockSize)
        {
            if(blockSize % 8 != 0)
            {
                throw new Exception("Invalid block size.");
            }

            var blockByteSize = blockSize / 8;
            var blocks = new List<BitArray>();

            for (var i = 0; i < message.Length; i += blockByteSize)
            {
                var block = new byte[blockByteSize];
                Array.Copy(message, i, block, 0, blockByteSize);
                blocks.Add(new BitArray(block));
            }

            return blocks;
        }
       
        private static byte[] CombineBlocks(List<BitArray> data)
        {
            var blocks = new List<byte[]>();

            foreach(var bitArray in data)
            {
                blocks.Add(bitArray.ToByteArray());
            }

            return blocks.SelectMany(e => e).ToArray();
        }
    }
}
