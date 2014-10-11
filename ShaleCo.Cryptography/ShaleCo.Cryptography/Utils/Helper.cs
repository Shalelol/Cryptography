﻿using System;
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

        public static int Base2(bool b0, bool b1)
        {
            if(b0)
            {
                if(b1)
                {
                    return 3;
                }
                else
                {
                    return 2;
                }
            }
            else
            {
                if(b1)
                {
                    return 1;
                }
                else
                {
                    return 0;
                }
            }
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
    }
}
