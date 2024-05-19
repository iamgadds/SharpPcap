using System;
using PacketDotNet;
using SharpPcap;

namespace BasicDemoNameSpace
{
    class BasicDemo
    {
        static Dictionary<int, (long sent, long received)> processData = new Dictionary<int, (long sent, long received)>();
        static object processDataLock = new object();
        static void NotMain(string[] args)
        {
            // Retrieve the device list
            var devices = CaptureDeviceList.Instance;

            // If no devices were found, print an error
            if (devices.Count < 1)
            {
                Console.WriteLine("No devices were found on this machine.");
                return;
            }

            // Print the list of devices
            Console.WriteLine("The following devices are available on this machine:");
            foreach (var dev in devices)
            {
                Console.WriteLine($"{dev.Name} - {dev.Description}");
            }

            // Select the first device
            var device = devices[4];

            // Open the device
            device.Open(DeviceModes.Promiscuous, 1000);

            // Register our handler function to the 'packet arrival' event
            device.OnPacketArrival += new PacketArrivalEventHandler(Device_OnPacketArrival);

            // Start capturing packets
            device.StartCapture();

            // Capture for 10 seconds
            Console.WriteLine("Capturing for 10 seconds...");
            System.Threading.Thread.Sleep(10000);

            // Stop the capture
            device.StopCapture();
            device.Close();

            //DisplayProcessData();

            Console.WriteLine("Capture complete.");
        }

        private static void Device_OnPacketArrival(object sender, PacketCapture e)
        {
            var rawPacket = e.GetPacket();
            var packet = PacketDotNet.Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
            //var packet = Packet.ParsePacket(e.GetPacket()!.LinkLayerType, e.GetPacket()!.Data);
            var tcpPacket = packet.Extract<TcpPacket>();

            if (tcpPacket != null)
            {
                var ip = packet.Extract<PacketDotNet.IPPacket>();
                if (ip != null)
                {
                    ip.SourceAddress = System.Net.IPAddress.Parse("1.2.3.4");
                    ip.DestinationAddress = System.Net.IPAddress.Parse("44.33.22.11");
                }
                var srcIp = ip!.SourceAddress;
                var dstIp = ip!.DestinationAddress;
                var srcPort = tcpPacket.SourcePort;
                var dstPort = tcpPacket.DestinationPort;

                //int pid = GetProcessIdForConnection(srcIp, srcPort, dstIp, dstPort);
                //if (pid != -1)
                //{
                //    lock (processDataLock)
                //    {
                //        if (!processData.ContainsKey(pid))
                //        {
                //            processData[pid] = (0, 0);
                //        }

                //        var data = processData[pid];
                //        data.received += tcpPacket.PayloadData.Length;
                //        data.sent += tcpPacket.PayloadData.Length;
                //        processData[pid] = data;
                //    }
                //}
            }
        }
    }
}

