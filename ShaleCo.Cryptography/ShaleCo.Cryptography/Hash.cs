using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using System.Threading.Tasks;
using ShaleCo.Cryptography.Utils;

namespace ShaleCo.Cryptography
{
    public enum HashTypes
    {
        DEFAULT,
        SHA3,
        SHALE
    }

    public static class Hash
    {
        public static byte[] GetHash(this string str, HashTypes type = HashTypes.DEFAULT)
        {
            switch(type)
            {
                case HashTypes.DEFAULT:
                    return BitConverter.GetBytes(str.GetHashCode());
                case HashTypes.SHA3:
                    return SHA3(str);
                case HashTypes.SHALE:
                    return SHALE(str);
            }

            throw new ArgumentException("HashType does not exist");
        }

        private static byte[] SHALE(string str)
        {
            var bytes = str.GetBytes();
            var paddedBytes = Helper.Padding(bytes, 4);

            var hash = new byte[4];
            Array.Copy(paddedBytes, 0, hash, 0, 4);

            for(var i = 3; i < paddedBytes.Length - 1; i = i + 4)
            {
                hash[0] = (byte) (hash[0] ^ paddedBytes[i + 1]);
                hash[1] = (byte) (hash[1] ^ paddedBytes[i + 2]);
                hash[2] = (byte) (hash[2] ^ paddedBytes[i + 3]);
                hash[3] = (byte) (hash[3] ^ paddedBytes[i + 4]);
            }

            return hash;
        }

        private static byte[] SHA3(string str)
        {
            throw new NotImplementedException();
        }

        
    }
}
