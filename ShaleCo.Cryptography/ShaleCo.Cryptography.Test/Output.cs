using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ShaleCo.Cryptography.Test
{
    public static class Output
    {
        private static FileStream outStream;
        private static StreamWriter writer;
        private static TextWriter oldOut;
        public static void SetFileOutPut(string filePath)
        {
            oldOut = Console.Out;

            try
            {
                outStream = new FileStream(filePath, FileMode.OpenOrCreate, FileAccess.Write);
                writer = new StreamWriter(outStream);
            }
            catch (Exception e)
            {
                Console.WriteLine("Cannot open {0} for writing.", filePath);
                Console.WriteLine("Exception: {0}", e.Message);
                return;
            }

            Console.SetOut(writer);
        }

        public static void Dispose()
        {
            if (writer != null)
            {
                writer.Close();
            }

            if (outStream != null)
            {
                outStream.Close();
            }

            if(oldOut != null)
            {
                Console.SetOut(oldOut);
            }
        }
    }
}
