using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace ShaleCo.Cryptography
{
    public class RSAKeys
    {
        public RSAKeys(byte[] e, byte[] d, byte[] n)
        {
            this.Private = new RSAKey(e, n);
            this.Public = new RSAKey(d, n);
        }

        public RSAKey Private { get; set; }
        public RSAKey Public { get; set; }

        public override string ToString()
        {
            return string.Format("Private: {0} \r\n Public: {1} ", this.Private, this.Public);
        }
    }

    public class RSAKey
    {
        public RSAKey(byte[] unique, byte[] common)
        {
            this.Unique = unique;
            this.Common = common;
        }

        public byte[] Unique { get; set; }
        public byte[] Common { get; set; }

        public override string ToString()
        {
            var unique = new BigInteger(this.Unique);
            var common = new BigInteger(this.Common);

            return string.Format("\t{0}, \t{1}", unique, common);
        }
    }
}
