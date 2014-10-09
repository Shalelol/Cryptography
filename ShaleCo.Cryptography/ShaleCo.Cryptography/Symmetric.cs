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
        public static byte[] EncryptAES(byte[] key, byte[] message)
        {
            message = Padding(message);

            var blocks = BreakIntoBlocks(message, 128);

            foreach(var block in blocks)
            {
                for(var i = 0; i < 10; i++)
                {

                }
            }

            throw new NotImplementedException();
        }

        public static byte[] Padding(byte[] message)
        {
            var remainder = message.Length % 16;
            var padding = new byte[remainder];

            byte[] paddedBytes;


            using (MemoryStream stream = new MemoryStream())
            {
                stream.Write(message, 0, message.Length);
                stream.Write(padding, 0, padding.Length);

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
