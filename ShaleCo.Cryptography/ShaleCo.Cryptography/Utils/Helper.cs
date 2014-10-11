using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ShaleCo.Cryptography.Utils
{
    public static class Helper
    {
        public static byte[] GetBytes(this string str)
        {
            byte[] bytes = new byte[str.Length * sizeof(char)];
            System.Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
            return bytes;
        }

        public static List<T> LoadFile<T>(string relativeFilePath) where T : IConvertible
        {
            var list = new List<T>();
            var lines = File.ReadAllLines(Directory.GetCurrentDirectory() + relativeFilePath);
            foreach (var line in lines)
            {
                var items = line.Split(',');

                foreach(var item in items)
                {
                    list.Add((T)Convert.ChangeType(item, typeof(T)));
                }
            }

            return list;
        }

        public static BitArray LeftShift(this BitArray bitArray, int shiftIndex)
        {
            var newBitArray = bitArray.Clone() as BitArray;

            for(var i = 0; i < shiftIndex; i++)
            {
                var firstBit = newBitArray[0];

                for (var j = 1; j < newBitArray.Count; j++)
                {
                    newBitArray[j - 1] = newBitArray[j];
                }

                newBitArray[newBitArray.Count - 1] = firstBit;
            }

            return newBitArray;
        }
    }
}
