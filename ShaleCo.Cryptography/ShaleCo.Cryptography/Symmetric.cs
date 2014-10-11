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

        static Symmetric()
        {
            _subKeyGenPC1 = Helper.LoadFile<int>("/Resources/DES-SubKey-Generation-pc1.csv");
            _subKeyGenPC2 = Helper.LoadFile<int>("/Resources/DES-SubKey-Generation-pc2.csv");
            _subKeyGenLeftShift = Helper.LoadFile<int>("/Resources/DES-SubKey-Generation-leftshift.csv");
        }

        public static byte[] EncryptAES(byte[] key, string message)
        {
            var paddedMessage = Padding(message.GetBytes());

            var blocks = BreakIntoBlocks(paddedMessage, 64);
            var keys = GenerateSubKeys(key);

            foreach(var block in blocks)
            {
                for(var i = 0; i < 10; i++)
                {

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
        private static List<byte[]> BreakIntoBlocks(byte[] message, int blockSize)
        {
            if(blockSize % 8 != 0)
            {
                throw new Exception("Invalid block size.");
            }

            var blockByteSize = blockSize / 8;
            var blocks = new List<byte[]>();

            for (var i = 0; i < message.Length; i += blockByteSize)
            {
                var block = new byte[blockByteSize];
                Array.Copy(message, i, block, 0, blockByteSize);
                blocks.Add(block);
            }

            return blocks;
        }
    }
}
