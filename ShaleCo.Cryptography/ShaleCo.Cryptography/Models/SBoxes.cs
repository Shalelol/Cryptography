using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ShaleCo.Cryptography
{
    public class SBoxes
    {
        public SBoxes()
        {
            this.Boxes = new List<SBox>();
        }

        public SBoxes(string fileName) : this()
        {
            var lines = File.ReadAllLines(Directory.GetCurrentDirectory() + fileName);
            
            for(var i = 0; i < 8; i++)
            {
                var sBox = new SBox();
                var index = i * 5;

                for(var j = 1; j < 5; j++)
                {
                    sBox.Rows.Add(new SBoxRow(lines[index + j].Split(',')));
                }

                this.Boxes.Add(sBox);
            }
        }

        public List<SBox> Boxes { get; set; }
    }

    public class SBox
    {
        public SBox()
        {
            this.Rows = new List<SBoxRow>();
        }

        public List<SBoxRow> Rows { get; set; }
    }

    public class SBoxRow : List<int>
    {
        public SBoxRow(IEnumerable<string> numbers)
        {
            foreach(var number in numbers)
            {
                this.Add(Int32.Parse(number));
            }
        }
    }
}
