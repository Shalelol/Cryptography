using System;
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

        private static SBoxes _sBoxes;

        static Symmetric()
        {
            _subKeyGenPC1 = Helper.LoadFile<int>("/Resources/DES-SubKey-Generation-pc1.csv");
            _subKeyGenPC2 = Helper.LoadFile<int>("/Resources/DES-SubKey-Generation-pc2.csv");
            _subKeyGenLeftShift = Helper.LoadFile<int>("/Resources/DES-SubKey-Generation-leftshift.csv");
            _encryptionIP = Helper.LoadFile<int>("/Resources/DES-Encryption-IP.csv");
            _encryptionIPInverse = Helper.LoadFile<int>("/Resources/DES-Encryption-IPInverse.csv");
            _encryptionEBit = Helper.LoadFile<int>("/Resources/DES-Encryption-EBit-Table.csv");

            _sBoxes = new SBoxes("/Resources/DES-Encryption-SBoxes.csv");
        }

        public static byte[] EncryptAES(byte[] key, string message)
        {
            var paddedMessage = Padding(message.GetBytes());

            var blocks = BreakIntoBlocks(paddedMessage, 64);
            var keys = GenerateSubKeys(key);

            foreach(var block in blocks)
            {
                var initialPermutation = new BitArray(64);
                var left = new BitArray(32);
                var right = new BitArray(32);

                //Rearange bits according to IP (Initial permutation)
                for (var i = 0; i < 64; i++)
                {
                    initialPermutation[i] = block[_encryptionIP[i] - 1];
                }

                //Split bits into left and right 32 bit halves
                for (var i = 0; i < 32; i++)
                {
                    left[i] = initialPermutation[i];
                    right[i] = initialPermutation[i + 32];
                }

                //Run through 16 rounds
                for (var i = 0; i < 16; i++)
                {
                    var oldLeft = left.Clone() as BitArray;
                    var oldRight = right.Clone() as BitArray;
                    var expanded = new BitArray(48);

                    //Expand right half according he the expansion box
                    for (var j = 0; j < 48; j++)
                    {
                        expanded[j] = oldRight[_encryptionEBit[j] - 1];
                    }

                    //XOR expanded block with 48 bit key
                    expanded = expanded.Xor(keys[i]);

                    var substituted = new List<bool>();

                    //Substitute expanded 48 block with 8 SBoxes to get back to 32 bits
                    for(var j = 0; j < 8; j++)
                    {
                        var index = j * 6;
                        var rowNumber = Helper.Base2(expanded[index], expanded[index + 5]);
                        var columnNumber = Helper.Base4(expanded[index + 1], expanded[index + 2], expanded[index + 3], expanded[index + 4]);
                        
                        var value = _sBoxes.Boxes.ElementAt(j).Rows.ElementAt(rowNumber).ElementAt(columnNumber);

                        var valueBits = new BitArray(BitConverter.GetBytes(value));

                        for(var k = 0; k < 4; k++)
                        {
                            substituted.Add(valueBits[k]);
                        }
                    }

                    left = oldRight;
                    right = new BitArray(substituted.ToArray());
                }
            }

            throw new NotImplementedException();
        }

        /// <summary>
        /// Padding is done usng PKSC7 padding.
        /// </summary>
        private static byte[] Padding(byte[] message)
        {
            var remainder = message.Length % 16;
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
        private static List<BitArray> GenerateSubKeys(byte[] key)
        {
            var k = new BitArray(key);
            var k1 = new BitArray(56);
            //Create K1 using PC-1 to re-arrange the key's bits
            for (var i = 0; i < 56; i++)
            {
                k1[i] = k[_subKeyGenPC1[i] - 1];
            }

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
            for (var i = 0; i < 28; i++)
            {
                c[0][i] = k1[i];
                d[0][i] = k1[i + 28];
            }

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
                    kList[i][j] = cd[i][_subKeyGenPC2[j] - 1];
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
    }
}
