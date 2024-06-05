using SharpPcapDemo.Models;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpPcapDemo
{
    public class DataUsageDetailedVM
    {
        public ConcurrentDictionary<int, MyProcess_Big> MyProcesses { get; set; }

        public DataUsageDetailedVM()
        {
            MyProcesses = new ConcurrentDictionary<int, MyProcess_Big>();
        }
    }
}
