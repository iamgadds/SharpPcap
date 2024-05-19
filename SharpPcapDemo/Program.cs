using System;
using System.Collections;
using System.Diagnostics;
using System.Drawing;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using PacketDotNet;
using PacketDotNet.Ieee80211;
using SharpPcap;
using SharpPcapDemo.Models;
using SharpPcapDemo.Utilities;
using System.Text.RegularExpressions;
using ProtocolType = PacketDotNet.ProtocolType;


class Program
{
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] localPort;
        public uint remoteAddr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] remotePort;
        public uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPTABLE_OWNER_PID
    {
        public uint dwNumEntries;
        public MIB_TCPROW_OWNER_PID table;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    public static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int pdwSize,
        bool bOrder,
        int ulAf,
        int TableClass,
        int Reserved
    );

    static Dictionary<int, MyProcess_Big> processData = new Dictionary<int, MyProcess_Big>();
    static object processDataLock = new object();
    private static byte[] defaultIPv4;
    private static byte[] defaultIPv6;
    private static byte[] localIPv4;
    private static byte[] localIPv6;
    public static string AdapterName { get; private set; }
    public static string IsNetworkOnline { get; set; }

    private static ConnectionStore connectionStore = new ConnectionStore();

    static (byte[], byte[]) myIpAddress;
    static void Main(string[] args)
    {
        NetworkChange.NetworkAddressChanged += NetworkChange_NetworkAddressChanged;
        IsNetworkOnline = "Disconnected";
        defaultIPv4 = new byte[]
            {
                0, 0, 0, 0
            };
        defaultIPv6 = new byte[]
        {
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0
        };
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

        myIpAddress = GetLocalIP();

        NetworkInterface myDevice = GetStatusUpConnectedDevice(null, null);

        // Select the device
        var device = devices[0];
        //devices.FirstOrDefault(x => x.Name!.Contains(myDevice!.Id));

        if (device == null)
        {
            Console.WriteLine($"No matching device found for: {myDevice.Id}");
            return;
        }


        Console.WriteLine($"Device Seelcted - {device.Name}");

        // Open the devices
        try
        {
            // Open the device
            device.Open(DeviceModes.Promiscuous, 1000);
        }
        catch (PcapException e)
        {
            Console.WriteLine($"Error opening device: {e.Message}");
            return;
        }


        // Register our handler function to the 'packet arrival' event
        device.OnPacketArrival += new PacketArrivalEventHandler(Device_OnPacketArrival);

        // Start capturing packets
        device.StartCapture();

        bool keepRunning = true;

        // Create a thread to listen for 'Enter' key press
        Thread inputThread = new Thread(() =>
        {
            Console.WriteLine("Capture Started --> Press Enter to stop");
            Console.ReadLine();
            keepRunning = false;
            device.StopCapture();
            device.Close();
        });
        inputThread.Start();

        // Continuously display MyProcesses
        while (keepRunning)
        {
            Console.Clear(); // Clear the console before printing new data
            DisplayProcessData();
            Thread.Sleep(10000); // Wait for 10 second before printing again
        }        

        Console.WriteLine("Capture complete.");
    }

    private static void Device_OnPacketArrival(object sender, PacketCapture e)
    {
        
        var rawPacket = e.GetPacket();
        //Console.WriteLine($"Reached the Packet Arrival stage: {rawPacket.Data}");
        var packet = PacketDotNet.Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
        //var packet = Packet.ParsePacket(e.GetPacket()!.LinkLayerType, e.GetPacket()!.Data);
        var tcpPacket = packet.Extract<TcpPacket>();
        var udpPacket = packet.Extract<UdpPacket>();
        var ipPacket = packet.Extract<PacketDotNet.IPPacket>();

        if (tcpPacket != null)
        {
            var srcIp = ipPacket!.SourceAddress;
            var dstIp = ipPacket!.DestinationAddress;
            var srcPort = tcpPacket.SourcePort;
            var dstPort = tcpPacket.DestinationPort;

            //Console.WriteLine($"Captured Packet: {ipPacket.SourceAddress}:{tcpPacket.SourcePort} -> {ipPacket.DestinationAddress}:{tcpPacket.DestinationPort}, Payload Length: {tcpPacket.PayloadData.Length}");
            ProcessPacket(srcIp, srcPort, dstIp, dstPort, tcpPacket.PayloadData.Length);
        }
        else if (udpPacket != null)
        {
            //ProcessPacket(ip!.SourceAddress, udpPacket.SourcePort, ip!.DestinationAddress, udpPacket.DestinationPort, udpPacket.PayloadData.Length);
        }
    }

    private static void ProcessPacket(IPAddress srcIp, ushort srcPort, IPAddress dstIp, ushort dstPort, int payloadLength)
    {
       // Console.WriteLine($"Packet: {srcIp}:{srcPort} -> {dstIp}:{dstPort}");

        int pid = GetProcessIdForConnection(srcIp, srcPort, dstIp, dstPort);
        //Console.WriteLine($"PID: {pid}");
        if (pid != -1 && pid != 0)
        {
            lock (processDataLock)
            {
                var data = new MyProcess_Big();
                if (!processData.ContainsKey(pid))
                {
                    processData[pid] = new MyProcess_Big();
                    processData[pid] = GetProcessDetails(pid);
                }

                if (processData[pid] != null)
                {
                    data = processData[pid];
                    data!.CurrentDataSent = payloadLength;
                    data!.CurrentDataRcvd = payloadLength;
                    // Assuming your machine's IP address is in myIpAddress
                    if (srcIp.GetAddressBytes().SequenceEqual(myIpAddress.Item1) || srcIp.GetAddressBytes().SequenceEqual(myIpAddress.Item2))
                    {
                        // Outgoing packet
                        data!.TotalDataSent += payloadLength;
                    }
                    else if (dstIp.GetAddressBytes().SequenceEqual(myIpAddress.Item1) || dstIp.GetAddressBytes().SequenceEqual(myIpAddress.Item2))
                    {
                        // Incoming packet
                        data!.TotalDataRcvd += payloadLength;
                    }
                    else
                    {
                        data!.TotalDataSent += payloadLength;
                    }

                    processData[pid] = data;
                    //Console.WriteLine($"Here we have inputed the data to our Dictionary :{data}");
                }
            }
        }
        else{
            Console.WriteLine($"Pid: {pid}");
        }
    }

    private static MyProcess_Big GetProcessDetails(int pid)
    {        
        try
        {
            var process = Process.GetProcessById(pid);
           // Console.WriteLine($"Here We get the processId {pid} and the name is {process.ProcessName}");
            MyProcess_Big myData = new MyProcess_Big();
            myData.Name = process.ProcessName;
            if (process.MainModule != null)
            {
                myData.IsSystemApp = process.MainModule.FileName!.ToLower().Contains("system");
               // myData.Icon = Icon.ExtractAssociatedIcon(process.MainModule.FileName);
            }

            return myData;
        }
        catch (Exception ex)
        {
            // Log any exceptions that occur
            Debug.WriteLine($"Exception while retrieving process icon: {ex.Message}");
            return null;
        }
    }

    private static int GetProcessIdForConnection(IPAddress srcIp, ushort srcPort, IPAddress dstIp, ushort dstPort)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return GetProcessIdForConnectionWindows(srcIp, srcPort, dstIp, dstPort);
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            //return NetworkUtils.GetProcessIdForConnectionMacOS(srcIp.ToString(), srcPort, dstIp.ToString(), dstPort);
            return GetProcessIdForMacOSConnection(srcIp.ToString(),srcPort,dstIp.ToString(),dstPort);
        }
        else
        {
            throw new PlatformNotSupportedException("Only Windows and macOS are supported.");
        }
    }

    private static int GetProcessIdForConnectionWindows(IPAddress srcIp, ushort srcPort, IPAddress dstIp, ushort dstPort)
    {
        int bufferSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, 2, 5, 0);
        IntPtr tcpTablePtr = Marshal.AllocHGlobal(bufferSize);

        try
        {
            uint result = GetExtendedTcpTable(tcpTablePtr, ref bufferSize, true, 2, 5, 0);
            if (result != 0) return -1;

            int numEntries = Marshal.ReadInt32(tcpTablePtr);
            IntPtr rowPtr = new IntPtr(tcpTablePtr.ToInt64() + 4);
            int rowSize = Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID));

            for (int i = 0; i < numEntries; i++)
            {
                var row = (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_TCPROW_OWNER_PID));
                IPAddress localIp = new IPAddress(BitConverter.GetBytes(row.localAddr));
                IPAddress remoteIp = new IPAddress(BitConverter.GetBytes(row.remoteAddr));

                ushort localPort = BitConverter.ToUInt16(new byte[] { row.localPort[1], row.localPort[0] }, 0);
                ushort remotePort = BitConverter.ToUInt16(new byte[] { row.remotePort[1], row.remotePort[0] }, 0);

                // Debug output to help trace the issue
                //Console.WriteLine($"Checking connection: {localIp}:{localPort} -> {remoteIp}:{remotePort}");

                if ((localIp.Equals(srcIp) && localPort == srcPort && remoteIp.Equals(dstIp) && remotePort == dstPort) ||
                    (localIp.Equals(dstIp) && localPort == dstPort && remoteIp.Equals(srcIp) && remotePort == srcPort))
                {
                    return (int)row.owningPid;
                }
                rowPtr = new IntPtr(rowPtr.ToInt64() + rowSize);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(tcpTablePtr);
        }

        return -1;
    }


private static int GetProcessIdForMacOSConnection(string srcIp, int srcPort, string dstIp, int dstPort)
{
    // Construct the command to check for established connections
    string command = $"lsof -i TCP -n -P | grep ESTABLISHED";
    var processStartInfo = new System.Diagnostics.ProcessStartInfo
    {
        FileName = "/bin/bash",
        Arguments = $"-c \"{command}\"",
        RedirectStandardOutput = true,
        UseShellExecute = false,
        CreateNoWindow = true
    };

    using (var process = new System.Diagnostics.Process { StartInfo = processStartInfo })
    {
        process.Start();
        string output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();

        // Parse the output to find the PID for the matching connection
        string[] lines = output.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (string line in lines)
        {
            // Extract fields from the line
            string[] fields = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);

            // Check if the line matches the criteria
            if (fields.Length >= 9 && fields[0] != "COMMAND" && fields[8].Contains("->") && fields[9] == "(ESTABLISHED)")
            {
                // Extract source IP and port
                string[] srcFields = fields[8].Split(new[] { "->" }, StringSplitOptions.RemoveEmptyEntries);
                string[] srcIpPort = srcFields[0].Split(':');
                string srcIpExtracted = srcIpPort[0];
                int srcPortExtracted = int.Parse(srcIpPort[1]);

                // Extract destination IP and port
                string[] dstIpPort = srcFields[1].Split(':');
                string dstIpExtracted = dstIpPort[0];
                int dstPortExtracted = int.Parse(dstIpPort[1]);

                int pid;
                    if (int.TryParse(fields[1], out pid))
                    {
                        //Console.WriteLine($"Process Id {pid}");
                        connectionStore.AddConnection(new ConnectionInfo
                        {
                            SourceIp = srcIpExtracted,
                            SourcePort = srcPortExtracted,
                            DestinationIp = dstIpExtracted,
                            DestinationPort = dstPortExtracted,
                            ProcessId = pid
                        });
                    }
                
            }
        }
        return connectionStore.GetProcessId(srcIp, srcPort, dstIp, dstPort);
    }

}

public static int GetProcessIdForPacket(IPAddress sourceIp, ushort sourcePort, IPAddress destinationIp, ushort destinationPort, ProtocolType protocol)
{
    int[] pids = new int[1024];
    int bytesProcessed;
    int err = proc_listpids(pids, pids.Length, out bytesProcessed);
    if (err != 0)
    {
        Console.WriteLine($"Error getting process list: {err}");
        return -1;
    }

    for (int i = 0; i < bytesProcessed / sizeof(int); i++)
    {
        int pid = pids[i];
        if (IsProcessAssociatedWithConnection(pid, sourceIp, sourcePort, destinationIp, destinationPort, protocol))
        {
            return pid;
        }
    }

    return -1;
}

private static bool IsProcessAssociatedWithConnection(int pid, IPAddress sourceIp, ushort sourcePort, IPAddress destinationIp, ushort destinationPort, ProtocolType protocol)
{
    int[] fds = new int[1024];
    int bytesProcessed;
    int err = proc_pidinfo(pid, PROC_PIDFDVNODES, IntPtr.Zero, 0, IntPtr.Zero, 0);
    if (err <= 0)
    {
        return false;
    }

    byte[] buffer = new byte[err];
    IntPtr ptr = Marshal.AllocHGlobal(err);
    err = proc_pidinfo(pid, PROC_PIDFDVNODES, ptr, err, IntPtr.Zero, 0);
    if (err <= 0)
    {
        Marshal.FreeHGlobal(ptr);
        return false;
    }

    Marshal.Copy(ptr, buffer, 0, err);
    Marshal.FreeHGlobal(ptr);

    IntPtr iter = IntPtr.Zero;
    for (int i = 0; i < err; i += Marshal.SizeOf(typeof(int)))
    {
        int fd = BitConverter.ToInt32(buffer, i);
        int len;
        IntPtr sockAddr = IntPtr.Zero;
        int sockAddrLen = 0;

        err = proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, out sockAddr, out sockAddrLen);
        if (err == 0 && sockAddr != IntPtr.Zero)
        {
            if (IsSockAddrMatchingConnection(sockAddr, sockAddrLen, sourceIp, sourcePort, destinationIp, destinationPort, protocol))
            {
                Marshal.FreeHGlobal(sockAddr);
                return true;
            }
            Marshal.FreeHGlobal(sockAddr);
        }
    }

    return false;
}

private static bool IsSockAddrMatchingConnection(IntPtr sockAddr, int sockAddrLen, IPAddress sourceIp, ushort sourcePort, IPAddress destinationIp, ushort destinationPort, ProtocolType protocol)
{
    return true;
    // if (protocol != ProtocolType.Tcp)
    //     return false;

    // // Ensure the sockaddr length is at least the size of a sockaddr_in structure
    // if (sockAddrLen < Marshal.SizeOf(typeof(SockaddrIn)))
    //     return false;

    // // Convert the sockaddr pointer to a sockaddr_in structure
    // SockaddrIn socketAddress = (SockaddrIn)Marshal.PtrToStructure(sockAddr, typeof(SockaddrIn));

    // // Check the address family
    // if (socketAddress.sin_family != AddressFamily.InterNetwork)
    //     return false;

    // // Extract the IP address and port from the sockaddr_in structure
    // byte[] addressBytes = new byte[4];
    // Array.Copy(socketAddress.sin_addr.Bytes, addressBytes, 4);
    // IPAddress ipAddress = new IPAddress(addressBytes);
    // ushort port = (ushort)IPAddress.NetworkToHostOrder((short)socketAddress.sin_port);

    // // Check if the IP address and port match the source or destination
    // bool isSourceMatch = (ipAddress.Equals(sourceIp) && port == sourcePort);
    // bool isDestinationMatch = (ipAddress.Equals(destinationIp) && port == destinationPort);

    // return isSourceMatch || isDestinationMatch;
}

// [StructLayout(LayoutKind.Sequential)]
// private struct SockaddrIn
// {
//     public ushort sin_family;
//     public ushort sin_port;
//     public InAddr sin_addr;
//     public byte sin_zero; // Padding to make the struct size correct

//     public SockaddrIn(ushort family, ushort port, byte[] address)
//     {
//         sin_family = family;
//         sin_port = port;
//         sin_addr = new InAddr(address);
//         sin_zero = 0;
//     }

//     [StructLayout(LayoutKind.Explicit)]
//     public struct InAddr
//     {
//         [FieldOffset(0)]
//         public byte s_b1;
//         [FieldOffset(1)]
//         public byte s_b2;
//         [FieldOffset(2)]
//         public byte s_b3;
//         [FieldOffset(3)]
//         public byte s_b4;

//         [FieldOffset(0)]
//         public uint S_un;

//         public byte[] Bytes;

//         public InAddr(byte[] address)
//         {
//             Bytes = new byte[4];
//             Array.Copy(address, Bytes, 4);
//         }
//     }
// }


private const int PROC_PIDFDVNODES = 1;
private const int PROC_PIDFDSOCKETINFO = 5;

[DllImport("/usr/lib/libproc.dylib")]
private static extern int proc_listpids(int[] buffer, int bufferSize, out int bytesProcessed);

[DllImport("/usr/lib/libproc.dylib")]
private static extern int proc_pidinfo(int pid, int flavor, IntPtr arg, int argSize, IntPtr buffer, int bufferSize);

[DllImport("/usr/lib/libproc.dylib")]
private static extern int proc_pidfdinfo(int pid, int fd, int flavor, out IntPtr buffer, out int bufferSize);

    private static void DisplayProcessData()
    {
        Console.WriteLine("\nData usage by process:");
        if (processData != null)
        {
           // Console.WriteLine($"Adapter: {netProc.AdapterName}, Download Speed: {netProc.DownloadSpeed}, Upload Speed: {netProc.UploadSpeed}");
           // Console.WriteLine($"Current Session:  Download Data: {netProc.CurrentSessionDownloadData}, Upload Data: {netProc.CurrentSessionUploadData} ");
            Console.WriteLine("------------------------------------");
            Console.WriteLine("MyProcesses:");
            foreach (var process in processData)
            { 
                if (process.Value != null)
                {
                    Console.WriteLine($"Process Name: {process.Value.Name} ({process.Key}) , IsSytem: {process.Value.IsSystemApp}, CurrentDataRecv: {process.Value.CurrentDataRcvd}, CurrentDataSend: {process.Value.CurrentDataSent}, TotalDataRecieved: {process.Value.TotalDataRcvd}, TotalDataSent: {process.Value.TotalDataSent}");
                }
            }
            Console.WriteLine("-------------------------------------");
        }
    }

    /// <summary>
    /// returns local IP (IPv4, IPv6)
    /// </summary>
    /// <returns></returns>
    private static (byte[], byte[]) GetLocalIP()
    {
        byte[] tempv4 = defaultIPv4;
        byte[] tempv6 = defaultIPv6;

        // IPv6
        using (Socket socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, 0))
        {
            try
            {
                socket.Connect("2001:4860:4860::8888", 65530);
                IPEndPoint? endPoint = socket.LocalEndPoint as IPEndPoint;
                if (endPoint != null)
                    tempv6 = endPoint.Address.GetAddressBytes();
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.Message);
            }
        }

        // IPv4
        using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, 0))
        {
            try
            {
                socket.Connect("8.8.8.8", 65530);
                IPEndPoint? endPoint = socket.LocalEndPoint as IPEndPoint;
                if (endPoint != null)
                    tempv4 = endPoint.Address.GetAddressBytes();
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.Message);
            }
        }

        return (tempv4, tempv6);
    }

    private static NetworkInterface GetStatusUpConnectedDevice(object? sender, EventArgs? e)
    {
        bool networkAvailable = false;
        NetworkInterface[] adapters = NetworkInterface.GetAllNetworkInterfaces();
        foreach (NetworkInterface n in adapters)
        {
            if (n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            {
                if (n.OperationalStatus == OperationalStatus.Up) //if there is a connection
                {
                    myIpAddress = GetLocalIP(); //get assigned ip

                    IPInterfaceProperties adapterProperties = n.GetIPProperties();
                    if (adapterProperties.GatewayAddresses.FirstOrDefault() != null)
                    {
                        foreach (UnicastIPAddressInformation ip in adapterProperties.UnicastAddresses)
                        {
                            if (ByteArray.Compare(ip.Address.GetAddressBytes(), myIpAddress.Item1))
                            {
                                if (localIPv4 == myIpAddress.Item1) //this is to prevent this event from firing multiple times during 1 connection change
                                    break;
                                else
                                    localIPv4 = myIpAddress.Item1;

                                networkAvailable = true;
                                AdapterName = n.Name;
                                if (n.NetworkInterfaceType == NetworkInterfaceType.Wireless80211)
                                    //AdapterName += "(" + NativeWifi.EnumerateConnectedNetworkSsids()?.FirstOrDefault()?.ToString() + ")";

                                    Debug.WriteLine(n.Name + " is up " + ", IP: " + ip.Address.ToString());

                                return n;
                            }
                            else if (ByteArray.Compare(ip.Address.GetAddressBytes(), myIpAddress.Item2))
                            {
                                if (localIPv6 == myIpAddress.Item2) //this is to prevent this event from firing multiple times during 1 connection change
                                    break;
                                else
                                    localIPv6 = myIpAddress.Item2;

                                networkAvailable = true;
                                AdapterName = n.Name;
                                if (n.NetworkInterfaceType == NetworkInterfaceType.Wireless80211)
                                    //AdapterName += "(" + NativeWifi.EnumerateConnectedNetworkSsids()?.FirstOrDefault()?.ToString() + ")";

                                    Debug.WriteLine(n.Name + " is up " + ", IP: " + ip.Address.ToString());

                                return n;
                            }
                        }
                    }
                }
            }
        }

        return null;
    }

    private static void NetworkChange_NetworkAddressChanged(object? sender, EventArgs? e)
    {
        GetStatusUpConnectedDevice(sender, e);
    }
}

