using SharpPcapDemo;
using SharpPcapDemo.Models;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;




class Program : INotifyPropertyChanged, IDisposable
{


    #region Properties
    private DataUsageDetailedVM? dudvm; 
    private NetworkProcess? netProc;
    private SocketConnection? socketConnection;

    private long _tcpPacketsLost = 0;


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


    private string? networkStatus;
    public string? NetworkStatus
    {
        get { return networkStatus; }
        set { networkStatus = value; OnPropertyChanged("NetworkStatus"); }
    }

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


    public async Task Main(string[] args)
    {
        using (var cancellationTokenSource = new CancellationTokenSource())
        {
            // Start the WebSocket server in a separate task
            socketConnection = new SocketConnection(RestartApplication);
            //var socketTask = socketConnection.StartConnectionAsync();


            Console.WriteLine("Handshake Successful");
            DownloadSpeed = 0;
            UploadSpeed = 0;


            networkStatus = "";
            dudvm = new DataUsageDetailedVM();


            InitialiseNetproc();


            // Continuously display MyProcesses
            while (cancellationTokenSource != null && !cancellationTokenSource.IsCancellationRequested)
            {
                //await SendProcessDataAsync();
                DisplayProcessData();
                Thread.Sleep(4000); // Wait for 4 seconds before sending data again
            }
        }
    }


    private void RestartApplication()
    {
        if (netProc != null)
        {
            netProc.Dispose();
            netProc = null;
        }
        InitialiseNetproc();
    }

    private void InitialiseNetproc()
    {
        try
        {
            netProc = new NetworkProcess();
            netProc.PropertyChanged += NetProc_PropertyChanged;
            netProc.Initialize(); // Have to call this after subscribing to property changed
        }
        catch (Exception ex)
        {
            Debug.WriteLine("Error in Initialising NetProc: ", ex.Message);
        }
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
                if (netProc?.IsNetworkOnline == "Disconnected")
                {
                    NetworkStatus = "Disconnected";
                    if (dudvm?.MyProcesses.Count() > 0)
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
                    NetworkStatus = "Connected : " + netProc?.IsNetworkOnline;
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
        UpdateDetailedTab();
    }


    private void UpdateDetailedTab()
    {
        if (netProc?.MyProcesses != null && netProc.MyProcessesBuffer != null && dudvm?.MyProcesses != null)
        {
            foreach (KeyValuePair<int, MyProcess_Big> app in dudvm.MyProcesses)
            {
                dudvm.MyProcesses[app.Key].CurrentDataRecv = 0;
                dudvm.MyProcesses[app.Key].CurrentDataSend = 0;
            }


            netProc.IsBufferTime = true;


            //this dictionary is locked from being accessible by the other threads like the network data capture Recv()
            lock (netProc.MyProcesses)
            {
                foreach (KeyValuePair<string, MyProcess_Small?> app in netProc.MyProcesses) //the contents of this loops remain only for a sec (related to NetworkProcess.cs=>CaptureNetworkSpeed())
                {
                    int processid = ProcessPacket(app.Value!.IpAddress, app.Value!.Port);


                    if (processid <= 0)
                    {
                        _tcpPacketsLost +=1;
                        continue;
                    }


                    if (!dudvm.MyProcesses.ContainsKey(processid))
                    {
                        dudvm.MyProcesses.TryAdd(processid, new MyProcess_Big("", 0, 0, 0, 0));


                        if (string.IsNullOrWhiteSpace(dudvm.MyProcesses[processid].Name))
                        {
                            MyProcess_Big? details = GetProcessDetails(processid);
                            if (details != null)
                            {
                                dudvm.MyProcesses[processid].Name = details.Name;
                                dudvm.MyProcesses[processid].IsSystemApp = details.IsSystemApp;
                            }
                        }
                    }
                    dudvm.MyProcesses[processid].CurrentDataRecv = app.Value!.CurrentDataRecv;
                    dudvm.MyProcesses[processid].CurrentDataSend = app.Value!.CurrentDataSend;
                    dudvm.MyProcesses[processid].TotalDataRecv += app.Value!.CurrentDataRecv;
                    dudvm.MyProcesses[processid].TotalDataSend += app.Value!.CurrentDataSend;
                    dudvm.MyProcesses[processid].Port = app.Value!.Port;
                    dudvm.MyProcesses[processid].NON_TCP_PACKETS = netProc!.NonTcpPackets;
                    dudvm.MyProcesses[processid].PACKETS_LOST = _tcpPacketsLost;




                }
                netProc.MyProcesses.Clear();
            }


            netProc.IsBufferTime = false;


            lock (netProc.MyProcessesBuffer)
            {
                foreach (KeyValuePair<string, MyProcess_Small?> app in netProc.MyProcessesBuffer) //the contents of this loops remain only for a sec (related to NetworkProcess.cs=>CaptureNetworkSpeed())
                {
                    int processid = ProcessPacket(app.Value!.IpAddress, app.Value!.Port);


                    if (processid <= 0)
                    {
                        _tcpPacketsLost +=1;
                        continue;
                    }


                    if (!dudvm.MyProcesses.ContainsKey(processid))
                    {
                        dudvm.MyProcesses.TryAdd(processid, new MyProcess_Big("", 0, 0, 0, 0));


                        if (string.IsNullOrWhiteSpace(dudvm.MyProcesses[processid].Name))
                        {
                            MyProcess_Big? details = GetProcessDetails(processid);
                            if (details != null)
                            {
                                dudvm.MyProcesses[processid].Name = details.Name;
                                dudvm.MyProcesses[processid].IsSystemApp = details.IsSystemApp;
                            }
                        }
                    }
                    dudvm.MyProcesses[processid].CurrentDataRecv = app.Value!.CurrentDataRecv;
                    dudvm.MyProcesses[processid].CurrentDataSend = app.Value!.CurrentDataSend;
                    dudvm.MyProcesses[processid].TotalDataRecv += app.Value!.CurrentDataRecv;
                    dudvm.MyProcesses[processid].TotalDataSend += app.Value!.CurrentDataSend;
                    dudvm.MyProcesses[processid].Port = app.Value!.Port;
                    dudvm.MyProcesses[processid].NON_TCP_PACKETS = netProc!.NonTcpPackets;
                    dudvm.MyProcesses[processid].PACKETS_LOST = _tcpPacketsLost;


                    netProc.MyProcessesBuffer.Clear();
                }
            }
        }
    }


    private int ProcessPacket(IPAddress? ip, int port)
    {
        return GetProcessIdForConnection(ip, port);
        
    }


    private MyProcess_Big? GetProcessDetails(int pid)
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


    private  int GetProcessIdForConnection(IPAddress? ip, int port)
    {
        return GetProcessIdForMacOSConnection(ip?.ToString(), port);
    }


        private int GetProcessIdForMacOSConnection(string? ip, int? port)
    {
        if (string.IsNullOrEmpty(ip) || port <= 0)
    {
        return -1;
    }

    
    // Determine if the IP is IPv6
    bool isIPv6 = ip.Contains(":");

    // Construct the netstat command
    string command = "netstat -anvp tcp | grep ESTABLISHED";

    var processStartInfo = new ProcessStartInfo
    {
        FileName = "/bin/bash",
        Arguments = $"-c \"{command}\"",
        RedirectStandardOutput = true,
        UseShellExecute = false,
        CreateNoWindow = true
    };

    using (var process = new Process { StartInfo = processStartInfo })
    {
        process.Start();
        string output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();

        // Split netstat output into lines
        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        foreach (var line in lines)
        {
            // Parse each line to match IP and port
            var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 9) continue;

            string localAddress = parts[3]; // Local address (e.g., 192.168.0.116.57430)
            string remoteAddress = parts[4]; // Remote address (e.g., 52.168.117.170.443)
            string pidString = parts[8]; // PID (e.g., 726)

            // Format the IP and port for matching
            string formattedAddress = isIPv6 
                ? $"[{ip}]:{port}"  // IPv6 format with square brackets
                : $"{ip}.{port}";   // IPv4 format with dot-separated port

            // Check if the remote address matches the formatted IP and port
            if (remoteAddress.Contains(formattedAddress))
            {
                if (int.TryParse(pidString, out int pid))
                {
                    return pid; // Return the matched PID
                }
            }
        }
    }

    return -1; // PID not found 
    }
    private void DisplayProcessData()
    {
        Console.WriteLine("\nData usage by process:");
         
        if (dudvm != null && dudvm.MyProcesses != null)
        {
            
            Console.WriteLine("------------------------------------");
            Console.WriteLine("MyProcesses:");
            foreach (var process in dudvm.MyProcesses)
            {
                Console.WriteLine($"Process ID: {process.Key}, Name: {process.Value.Name}, IsSystem: {process.Value.IsSystemApp}, TotalDataReceived: {process.Value.TotalDataRecv}, TotalDataSent: {process.Value.TotalDataSend}");
            }
            Console.WriteLine($"Packets other than tcp found: ${netProc!.NonTcpPackets} \n Packets lost due to process id not found: ${_tcpPacketsLost}");
            Console.WriteLine("------------------------------------");
        }
    }


    private async Task SendProcessDataAsync()
    {
        if (dudvm != null && dudvm.MyProcesses != null)
        {
            await socketConnection!.SendDataAsync(dudvm.MyProcesses);
        }
    }


    public void Dispose()
    {
        netProc!.PropertyChanged -= NetProc_PropertyChanged;
        socketConnection?.Dispose();
        _tcpPacketsLost = 0;
        if(netProc != null){
            netProc.Dispose();
            netProc = null;
        }
    }
}


class ProgramEntryPoint
{
    public static async Task Main(string[] args)
    {
        //async Task
        using (var program = new Program())
        {
            await program.Main(args);
        }
    }
}