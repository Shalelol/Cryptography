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
            return Encoding.ASCII.GetBytes(str);
        }

        public static string GetString(this byte[] bytes)
        {
            return Encoding.ASCII.GetString(bytes);
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

        public static byte[] ToByteArray(this BitArray data)
        {
            byte[] bytes = new byte[data.Length / 8];
            data.CopyTo(bytes, 0);
            return bytes;
        }

        public static int Base2(bool b0, bool b1)
        {
            if(b0)
                if(b1)
                    return 3;
                else
                    return 2;
            else
                if(b1)
                    return 1;
                else
                    return 0;
        }

        public static int Base4(bool b0, bool b1, bool b2, bool b3)
        {
            if (b0)
                if (b1)
                    if (b2)
                        if (b3)
                            return 15;
                        else
                            return 14;
                    else
                        if (b3)
                            return 13;
                        else
                            return 12;
                else
                    if (b2)
                        if (b3)
                            return 11;
                        else
                            return 10;
                    else
                        if (b3)
                            return 9;
                        else
                            return 8;
            else
                if (b1)
                    if (b2)
                        if (b3)
                            return 7;
                        else
                            return 6;
                    else
                        if (b3)
                            return 5;
                        else
                            return 4;
                else
                    if (b2)
                        if (b3)
                            return 3;
                        else
                            return 2;
                    else
                        if (b3)
                            return 1;
                        else
                            return 0;
        }

        public static void Log(this BitArray bitArray, string name = null, int grouping = 8)
        {
            Console.Write("{0} :", name);

            var count = 1;
            foreach(bool bit in bitArray)
            {
                Console.Write(bit ? 1 : 0);
                if (count % grouping == 0)
                {
                    Console.Write(" ");
                }
                count++;
            }
            Console.WriteLine();
        }

        public static string ByteArrayToDecimalString(byte[] bytes, int grouping = 8)
        {
            var sb = new StringBuilder();

            foreach(var b in bytes)
            {
                sb.Append(Convert.ToString(b, 2).PadLeft(8, '0'));
                sb.Append(" ");
            }

            return sb.ToString();
        }

        public static string ByteArrayToHexString(byte[] bytes)
        {
            var hex = BitConverter.ToString(bytes);
            return hex;
        }

        public static byte[] CombineByteArrays(params byte[][] arrays)
        {
            byte[] combined = new byte[arrays.Sum(e => e.Length)];
            var offset = 0;
            
            foreach(var array in arrays)
            {
                Buffer.BlockCopy(array, 0, combined, offset, array.Length);
                offset += array.Length;
            }

            return combined;
        }

        public static byte[] Padding(byte[] message, int blockSize)
        {
            int remainder;
            if (message.Length > blockSize)
            {
                remainder = message.Length % blockSize;
                if (remainder != 0)
                {
                    remainder = blockSize - remainder;
                }
            }
            else
            {
                remainder = blockSize - message.Length;
            }

            var padding = BitConverter.GetBytes(remainder)[0];
            var paddingList = new List<byte>();

            for (var i = 0; i < remainder; i++)
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

        public static byte[] ReversePadding(byte[] bytes)
        {
            int paddingNumber = bytes[bytes.Length - 1];

            if (paddingNumber > 7)
            {
                return bytes;
            }

            for (var i = 1; i <= paddingNumber; i++)
            {
                if (bytes[bytes.Length - i] != paddingNumber)
                {
                    return bytes;
                }
            }

            var newArray = bytes.Take(bytes.Length - paddingNumber).ToArray();

            return newArray;
        }
    }
}
