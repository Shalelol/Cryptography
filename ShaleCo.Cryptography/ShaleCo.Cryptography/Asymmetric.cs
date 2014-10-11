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
        private static List<int> _primeNumbers;
        private static Random _randomGenerator = new Random();

        static Asymmetric()
        {
            _primeNumbers = Helper.LoadFile<int>("/Resources/prime-numbers.csv");
        }

        public static byte[] RSA(byte[] e, byte[] n, byte[] m)
        {
            var key1 = new BigInteger(e);
            var key2 = new BigInteger(n);
            var message = new BigInteger(m);

            //equivilant of m ^ e % n (if e, n and m were 32bit integers) 
            var cipher = BigInteger.ModPow(message, key1, key2);

            return cipher.ToByteArray();
        }

        public static byte[] RSA(RSAKey key, byte[] m)
        {
            return RSA(key.Unique, key.Common, m);
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

            //This is a proof that e and d are correct
            //var test = (e * d) % toilent == 1 % toilent; 

            return new RSAKeys(d.ToByteArray(), e.ToByteArray(), n.ToByteArray());
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
            return new BigInteger(_primeNumbers.ElementAt(_randomGenerator.Next(0, 9999)));
        }

    }
}
