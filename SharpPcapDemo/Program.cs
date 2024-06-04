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
using System.ComponentModel;
using SharpPcapDemo;


class Program : INotifyPropertyChanged, IDisposable
{

    #region Properties
    private DataUsageDetailedVM dudvm;
    private NetworkProcess netProc;

    public long downloadSpeed;
    public long DownloadSpeed
    {
        get { return downloadSpeed; }
        set { downloadSpeed = value; OnPropertyChanged("DownloadSpeed"); }
    }
    public long uploadSpeed;

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged(string propName) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propName));


    public long UploadSpeed
    {
        get { return uploadSpeed; }
        set { uploadSpeed = value; OnPropertyChanged("UploadSpeed"); }
    }

    private string networkStatus;
    public string NetworkStatus
    {
        get { return networkStatus; }
        set { networkStatus = value; OnPropertyChanged("NetworkStatus"); }
    }

    private DateTime date1;
    private DateTime date2;

    private long initTodayTotalDownloadData = 0;
    private long initTodayTotalUploadData = 0;
    #endregion

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

    private (byte[], byte[]) myIpAddress;
    public void Main(string[] args)
    {
        DownloadSpeed = 0;
        UploadSpeed = 0;
        date1 = DateTime.Now;
        date2 = DateTime.Now;

        networkStatus = "";
        dudvm = new DataUsageDetailedVM();

        netProc = new NetworkProcess();
        netProc.PropertyChanged += NetProc_PropertyChanged;
        netProc.Initialize(); //have to call this after subscribing to property changer
        bool keepRunning = true;

        // Continuously display MyProcesses
        while (keepRunning)
        {
            Console.Clear(); // Clear the console before printing new data
            DisplayProcessData();
            Thread.Sleep(10000); // Wait for 10 second before printing again
        }        

        Console.WriteLine("Capture complete.");
    }

    private void NetProc_PropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        Stopwatch sw = new Stopwatch();
        sw.Start();
        switch (e.PropertyName)
        {
            case "DownloadSpeed":
                UpdateData();
                break;
            case "IsNetworkOnline":
                if (netProc.IsNetworkOnline == "Disconnected")
                {
                    NetworkStatus = "Disconnected";
                    if (dudvm.MyProcesses.Count() > 0)
                    {
                        dudvm.MyProcesses.Clear();
                        //foreach (var row in dudvm.MyProcesses.ToList())
                        //{
                        //    dudvm.MyProcesses.TryRemove(row);
                        //}
                    }
                }
                else
                {
                    NetworkStatus = "Connected : " + netProc.IsNetworkOnline;
                }
                break;
            default:
                break;
        }
        sw.Stop();
        // Debug.WriteLine($"elapsed time (NetProc): {sw.ElapsedMilliseconds}");
    }

    private void UpdateData()
    {
        date2 = DateTime.Now;

        UpdateDetailedTab();
    }

    private void UpdateDetailedTab()
    {
        if (netProc.MyProcesses != null && netProc.MyProcessesBuffer != null && dudvm.MyProcesses != null)
        {
            //foreach (KeyValuePair<string, MyProcess_Big> app in dudvm.MyProcesses)
            //{
            //    dudvm.MyProcesses[app.Key].CurrentDataRecv = 0;
            //    dudvm.MyProcesses[app.Key].CurrentDataSend = 0;
            //}

            netProc.IsBufferTime = true;

            //this dictionary is locked from being accessible by the other threads like the network data capture Recv()
            lock (netProc.MyProcesses)
            { 
                foreach (KeyValuePair<string, MyProcess_Small?> app in netProc.MyProcesses) //the contents of this loops remain only for a sec (related to NetworkProcess.cs=>CaptureNetworkSpeed())
                {
                    dudvm.MyProcesses.TryAdd(app.Key, new MyProcess_Big("", 0, 0, 0, 0));
                    dudvm.MyProcesses[app.Key].CurrentDataRecv = app.Value!.CurrentDataRecv;
                    dudvm.MyProcesses[app.Key].CurrentDataSend = app.Value!.CurrentDataSend;
                    dudvm.MyProcesses[app.Key].TotalDataRecv += app.Value!.CurrentDataRecv;
                    dudvm.MyProcesses[app.Key].TotalDataSend += app.Value!.CurrentDataSend;
                    dudvm.MyProcesses[app.Key].Port = app.Value!.Port;

                    if (string.IsNullOrWhiteSpace(dudvm.MyProcesses[app.Key].Name))
                    {
                        dudvm.MyProcesses[app.Key].ProcessId = ProcessPacket(app.Value.IpAddress, app.Value.Port);

                        MyProcess_Big details = GetProcessDetails(dudvm.MyProcesses[app.Key].ProcessId);
                        if (details != null)
                        {
                            dudvm.MyProcesses[app.Key].Name = details.Name;
                            dudvm.MyProcesses[app.Key].IsSystemApp = details.IsSystemApp;
                        }
                    }
                }
                netProc.MyProcesses.Clear();
            }

            netProc.IsBufferTime = false;

            lock (netProc.MyProcessesBuffer)
            {
                foreach (KeyValuePair<string, MyProcess_Small?> app in netProc.MyProcessesBuffer) //the contents of this loops remain only for a sec (related to NetworkProcess.cs=>CaptureNetworkSpeed())
                {
                    Debug.WriteLine("BUFFEEERRRRR!!!!!");
                    dudvm.MyProcesses.TryAdd(app.Key, new MyProcess_Big("", 0, 0, 0, 0));
                    dudvm.MyProcesses[app.Key].CurrentDataRecv += app.Value!.CurrentDataRecv;
                    dudvm.MyProcesses[app.Key].CurrentDataSend += app.Value!.CurrentDataSend;
                    dudvm.MyProcesses[app.Key].TotalDataRecv += app.Value!.CurrentDataRecv;
                    dudvm.MyProcesses[app.Key].TotalDataSend += app.Value!.CurrentDataSend;
                    dudvm.MyProcesses[app.Key].Port = app.Value!.Port;

                    if (string.IsNullOrWhiteSpace(dudvm.MyProcesses[app.Key].Name))
                    {
                        dudvm.MyProcesses[app.Key].ProcessId = ProcessPacket(app.Value.IpAddress, app.Value.Port);

                        MyProcess_Big details = GetProcessDetails(dudvm.MyProcesses[app.Key].ProcessId);
                        if (details != null)
                        {
                            dudvm.MyProcesses[app.Key].Name = details.Name;
                            dudvm.MyProcesses[app.Key].IsSystemApp = details.IsSystemApp;
                        }
                    }
                }

                netProc.MyProcessesBuffer.Clear();
            }
        }
    }

    private int ProcessPacket(IPAddress? ip, int port)
    {
        return GetProcessIdForConnection(ip, port);
        
    }

    private MyProcess_Big GetProcessDetails(int pid)
    {        
        try
        {
            var process = Process.GetProcessById(pid);
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

    private  int GetProcessIdForConnection(IPAddress ip, int port)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return GetProcessIdForConnectionWindows(ip, port);
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return GetProcessIdForMacOSConnection(ip.ToString(),port);
        }
        else
        {
            throw new PlatformNotSupportedException("Only Windows and macOS are supported.");
        }
    }

    private  int GetProcessIdForConnectionWindows(IPAddress ip, int port)
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
                IPAddress remoteIp = new IPAddress(BitConverter.GetBytes(row.remoteAddr));

                ushort remotePort = BitConverter.ToUInt16(new byte[] { row.remotePort[1], row.remotePort[0] }, 0);

                // Debug output to help trace the issue
                //Console.WriteLine($"Checking connection: {localIp}:{localPort} -> {remoteIp}:{remotePort}");

                if (remoteIp.Equals(ip) && remotePort == port)
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

    private  int GetProcessIdForMacOSConnection(string? ip, int? port)
{
    if (ip == null || port == null){
        Console.WriteLine($"Pid: -1 :null");
        return -1;
    }

    // Construct the command to check for established connections
    string command = $"lsof -i TCP@{ip}:{port} -n -P | grep ESTABLISHED";
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

            int pid;
                    if (int.TryParse(fields[1], out pid))
                    {
                        return pid;
                    }
        }
        Console.WriteLine($"Pid: -1 {ip}:{port}");
        return -1;
    }

}
    private void DisplayProcessData()
    {
        Console.WriteLine("\nData usage by process:");

        if (dudvm != null && dudvm.MyProcesses != null)
        {
            var groupedProcesses = dudvm.MyProcesses.Values
                .GroupBy(p => p.ProcessId)
                .Select(g => new
                {
                    ProcessId = g.Key,
                    Name = g.First().Name, // Assuming all instances have the same name
                    IsSystemApp = g.First().IsSystemApp, // Assuming all instances have the same IsSystemApp flag
                    TotalDataRecv = g.Sum(p => p.TotalDataRecv),
                    TotalDataSend = g.Sum(p => p.TotalDataSend)
                });

            Console.WriteLine("------------------------------------");
            Console.WriteLine("MyProcesses:");
            foreach (var process in groupedProcesses)
            {
                Console.WriteLine($"Process ID: {process.ProcessId}, Name: {process.Name}, IsSystem: {process.IsSystemApp}, TotalDataReceived: {process.TotalDataRecv}, TotalDataSent: {process.TotalDataSend}");
            }
            Console.WriteLine("------------------------------------");
        }
    }


    public void Dispose()
    {
    }
}

class ProgramEntryPoint
{
    public static void Main(string[] args)
    {
        //async Task
        using (var program = new Program())
        {
            program.Main(args);
        }
        //using (var socket = new SockerConnection())
        //{
        //  // await socket.StartConnectionAsync();
        //}
    }
}

