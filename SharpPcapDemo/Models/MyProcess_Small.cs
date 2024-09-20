using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace SharpPcapDemo.Models
{
    public class MyProcess_Small
    {
        public IPAddress? IpAddress { get; set; }

        public long CurrentDataRecv { get; set; }

        public long CurrentDataSend { get; set; }

        public int Port { get; set; }

        public MyProcess_Small(IPAddress? ip, long currentDataRecvP, long currentDataSendP, int port)
        {
            IpAddress = ip;
            CurrentDataRecv = currentDataRecvP;
            CurrentDataSend = currentDataSendP;
            Port = port;
        }
    }
}
