using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ShaleCo.Cryptography
{
    public static class Symmetric
    {
        private static List<int> _subKeyGenTable = new List<int>();

        static Symmetric()
        {
            var lines = File.ReadAllLines(Directory.GetCurrentDirectory() + "/Resources/DES-SubKey-Generation.csv");
            foreach (var line in lines)
            {
                var numbers = line.Split(',');

                foreach (var number in numbers)
                {
                    _subKeyGenTable.Add(Int32.Parse(number));
                }
            }
        }

        public static byte[] EncryptAES(byte[] key, string message)
        {
            var paddedMessage = Padding(message.GetBytes());

            var blocks = BreakIntoBlocks(paddedMessage, 64);

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
        public static byte[] Padding(byte[] message)
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


        public static List<byte[]> BreakIntoBlocks(byte[] message, int blockSize)
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
