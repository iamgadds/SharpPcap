using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpPcapDemo.Models
{
    public class MyProcess_Big
    {
        public string Name { get; set; }

        public long CurrentDataRcvd { get; set; }

        public long CurrentDataSent { get; set; }

        public long TotalDataRcvd { get; set; }

        public long TotalDataSent { get; set; }

        public bool? IsSystemApp { get; set; }

        public Icon? Icon { get; set; }
    }
}
