using ShaleCo.Cryptography.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace ShaleCo.Cryptography
{
    public static class Asymmetric
    {
        private static List<Int64> _primeNumbers;
        private static Random _randomGenerator = new Random();

        static Asymmetric()
        {
            _primeNumbers = Helper.LoadFile<Int64>("/Resources/prime-numbers.csv");
        }

        public static byte[] EncryptRSA(byte[] e, byte[] n, byte[] m)
        {
            var key1 = new BigInteger(e);
            var key2 = new BigInteger(n);
            var cipherText = new List<BigInteger>();

            var paddedMessage = Helper.Padding(m, 4);
            var blocks = BreakIntoBlocks(paddedMessage, 4, true);

            foreach(var block in blocks)
            {
                cipherText.Add(BigInteger.ModPow(block, key1, key2));
            }

            return Combineblocks(cipherText, 5);
        }

        public static byte[] DecryptRSA(byte[] e, byte[] n, byte[] c)
        {
            var key1 = new BigInteger(e);
            var key2 = new BigInteger(n);
            var message = new List<BigInteger>();

            var blocks = BreakIntoBlocks(c, 5);

            foreach(var block in blocks)
            {
                message.Add(BigInteger.ModPow(block, key1, key2));
            }

            var combinedBlocks = Combineblocks(message, 4);

            return Helper.ReversePadding(combinedBlocks);
        }

        public static byte[] EncryptRSA(RSAKey key, byte[] m)
        {
            return EncryptRSA(key.Unique, key.Common, m);
        }
        public static byte[] DecryptRSA(RSAKey key, byte[] m)
        {
            return DecryptRSA(key.Unique, key.Common, m);
        }

        public static RSAKeys GenerateRSAKeys()
        {
            var p = RandomPrime();
            var q = RandomPrime();

            while(q.Equals(p))
            {
                p = RandomPrime();
            }

            //n = p * q
            var n = BigInteger.Multiply(p, q);

            // toilent = (q - 1)(p - 1)
            var toilent = BigInteger.Multiply(q - 1, p - 1);
            //var toilent = BigInteger.Multiply(BigInteger.Subtract(p, BigInteger.One), BigInteger.Subtract(q, BigInteger.One));

            //pick e so that 1 < e < toilent and e is not a divisor of toilent
            var e = RandomPrime();
            while(e.CompareTo(toilent) >= 0 || GCD(e, toilent) != 1)
            {
                e = RandomPrime();
            }


            //Get the modular multiplicative inverse
            var d = ModInverse(e, toilent);

            return new RSAKeys(d.ToByteArray(), e.ToByteArray(), n.ToByteArray());
        }

        private static List<BigInteger> BreakIntoBlocks(byte[] message, int blockBitSize, bool addRoom = false)
        {
            var blockByteSize = blockBitSize;
            var blocks = new List<BigInteger>();

            for (var i = 0; i < message.Length; i += blockByteSize)
            {
                var block = addRoom ? new byte[blockByteSize + 1] : new byte[blockByteSize];
                Array.Copy(message, i, block, 0, blockByteSize);
                blocks.Add(new BigInteger(block));
            }

            return blocks;
        }

        private static byte[] Combineblocks(List<BigInteger> messages, int blockSize)
        {
            var blocks = new List<byte[]>();

            for (var i = messages.Count - 1; i >= 0; i-- )
            {
                blocks.Add(messages[i].ToByteArray());
            }

            for (var i = 0; i < blocks.Count; i++)
            {
                while( blocks[i].Length != blockSize)
                {
                    if (blocks[i].Length > blockSize)
                    {
                        var trimmed = new byte[blocks[i].Length - 1];
                        Buffer.BlockCopy(blocks[i], 0, trimmed, 0, blocks[i].Length - 1);
                        blocks[i] = trimmed;
                    }
                    else
                    {
                        var newBlock = new byte[blocks[i].Length + 1];
                        Buffer.BlockCopy(blocks[i], 0, newBlock, 0, blocks[i].Length);
                        blocks[i] = newBlock;
                    }
                }
            }

            return blocks.SelectMany(e => e).ToArray();
        }

        private static BigInteger ModInverse(BigInteger a, BigInteger b)
        {
            var dividend = a % b;
            var divisor = b;

            var lastX = BigInteger.One;
            var currentX = BigInteger.Zero;

            while (divisor.Sign > 0)
            {
                var quotient = BigInteger.Divide(dividend, divisor);
                var remainder = dividend % divisor;

                if (remainder.Sign <= 0)
                {
                    break;
                }

                var nextX = lastX - currentX * quotient;
                lastX = currentX;
                currentX = nextX;

                dividend = divisor;
                divisor = remainder;
            }

            if(divisor != BigInteger.One)
            {
                throw new Exception("Numbers are not relatively prime");
            }

            return (currentX.Sign < 0 ? currentX + b : currentX);
        }

        private static BigInteger GCD(BigInteger a, BigInteger b)
        {
            var quotient = b;
            var remainder = a % b;

            while(remainder != BigInteger.Zero)
            {
                var temp = remainder;
                remainder = quotient % remainder;
                quotient = temp;
            }

            return quotient;
        }

        private static BigInteger RandomPrime()
        {
            return new BigInteger(_primeNumbers.ElementAt(_randomGenerator.Next(0, _primeNumbers.Count - 1)));
        }

    }
}
