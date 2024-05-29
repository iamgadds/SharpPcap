using PacketDotNet;
using SharpPcap;
using SharpPcapDemo.Models;
using SharpPcapDemo.Utilities;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace SharpPcapDemo
{
    public class NetworkProcess : IDisposable
    {
        #region Private Properties
        private const int OneSec = 1000;

        private readonly byte[] defaultIPv4;
        private readonly byte[] defaultIPv6;
        private byte[] localIPv4;
        private byte[] localIPv6;

        //variables to create seperate running threads for updating the network speed
        private AsyncTask asyncTask_networkSpeed;

        //this is used to run the event tracing (kernelSession) in a seperate thread
        public Task? PacketTask;

        public string AdapterName { get; private set; }

        //memory to store the process network details temporarily before updating the views.
        public Dictionary<string, MyProcess_Small?>? MyProcesses { get; private set; }
        public Dictionary<string, MyProcess_Small?>? MyProcessesBuffer { get; private set; }

        /// <summary>
        /// why use this 'IsBufferTime'? 
        /// during its true state, the Recv() in NetworkProcess stores the incoming data to the netProc.MyProcessesBuffer dictionary.
        /// while its storing there, netProc.MyProcesses data is extracted to parse. Once done, this boolean is set to false
        /// during the false state, the Recv() function stores data in the netProc.MyProcesses dictionary
        /// during this, netProc.MyProcessesBuffer data is extracted to parse. 
        /// </summary>
        public bool IsBufferTime { get; set; }

        public long CurrentSessionDownloadData;

        public long CurrentSessionUploadData;

        public long UploadSpeed;

        private CancellationTokenSource cancellationTokenSource;
        #endregion

        #region Properties


        //---------- variables with property changers ------------//
        public long downloadSpeed;
        public long DownloadSpeed
        {
            get { return downloadSpeed; }
            set { downloadSpeed = value; OnPropertyChanged("DownloadSpeed"); }
        }

        private string isNetworkOnline = "error";
        public string IsNetworkOnline
        {
            get { return isNetworkOnline; }
            set { isNetworkOnline = value; OnPropertyChanged("IsNetworkOnline"); }
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnPropertyChanged(string propName) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propName));

        public (byte[], byte[]) myIpAddress;
        #endregion

        #region Constructor

        public NetworkProcess()
        {
            //initialize variables
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
            localIPv4 = defaultIPv4;
            localIPv6 = defaultIPv6;
            AdapterName = "";
            MyProcesses = new Dictionary<string, MyProcess_Small?>();
            MyProcessesBuffer = new Dictionary<string, MyProcess_Small?>();
            IsBufferTime = false;

            PacketTask = null;

            asyncTask_networkSpeed = new AsyncTask(1);

            CurrentSessionUploadData = 0;
            CurrentSessionDownloadData = 0;
            UploadSpeed = 0;
            DownloadSpeed = 0;
        }
        #endregion

        #region Initialize

        /// <summary>
        /// call after subscribing to the property handlers in the Program.cs
        /// </summary>
        public void Initialize()
        {
            IsNetworkOnline = "Disconnected";

            // Initialize the CancellationTokenSource
            cancellationTokenSource = new CancellationTokenSource();

            //subscribe address network address change
            NetworkChange.NetworkAddressChanged += NetworkChange_NetworkAddressChanged;

            //myIpAddress = GetLocalIP();
            var devices = CaptureDeviceList.Instance;
            NetworkInterface myDevice = GetStatusUpConnectedDevice(null, null);
            var device = devices.FirstOrDefault(x => x.Name!.Contains(myDevice!.Id));

            StartNetworkProcess(device);

        }

        #endregion

        #region Methods
        private void NetworkChange_NetworkAddressChanged(object? sender, EventArgs? e)
        {
            GetStatusUpConnectedDevice(sender, e);
        }

        private NetworkInterface GetStatusUpConnectedDevice(object? sender, EventArgs? e)
        {
            #pragma warning disable CS0219 // Variable is assigned but its value is never used
                        bool networkAvailable = false;
            #pragma warning restore CS0219 // Variable is assigned but its value is never used
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

            #pragma warning disable CS8603 // Possible null reference return.
                        return null;
            #pragma warning restore CS8603 // Possible null reference return.
        }

        /// <summary>
        /// returns local IP (IPv4, IPv6)
        /// </summary>
        /// <returns></returns>
        private (byte[], byte[]) GetLocalIP()
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

        public void StartNetworkProcess(ILiveDevice device)
        {
            PacketTask = Task.Run(() =>
            {
                // Open the devices
                try
                {
                    device.OnPacketArrival += new PacketArrivalEventHandler(Device_OnPacketArrival);
                    // Open the device
                    device.Open(DeviceModes.Promiscuous, 1000);

                    // Start capturing packets
                    device.StartCapture();
                }
                catch (PcapException e)
                {
                    Console.WriteLine($"Error opening device: {e.Message}");
                    return;
                }

                // Create a thread to listen for 'Enter' key press
                Thread inputThread = new Thread(() =>
                {
                    Console.WriteLine("Capture Started --> Press Enter to stop");
                    Console.ReadLine();
                    device.StopCapture();
                    device.Close();
                });
                inputThread.Start();
            });

            asyncTask_networkSpeed.Task = CaptureNetworkSpeed(); //start logging the speed

        }

        private async Task CaptureNetworkSpeed()
        {
            asyncTask_networkSpeed.CancelToken = new CancellationTokenSource();
            try
            {
                long tempDownload = 0;
                long tempUpload = 0;
                Debug.WriteLine("Operation Started : Network speed");
                while (await asyncTask_networkSpeed.Timer.WaitForNextTickAsync(asyncTask_networkSpeed.CancelToken.Token))
                {
                    #if DEBUG
                    Stopwatch sw1 = Stopwatch.StartNew();
                    #endif
                    UploadSpeed = (CurrentSessionUploadData - tempUpload) * 8;
                    DownloadSpeed = (CurrentSessionDownloadData - tempDownload) * 8;
                    //UploadSpeed = (CurrentSessionUploadData - tempUpload);
                    //DownloadSpeed = (CurrentSessionDownloadData - tempDownload);

                    tempUpload = CurrentSessionUploadData;
                    tempDownload = CurrentSessionDownloadData;
                    #if DEBUG
                    sw1.Stop();
                    Debug.WriteLine($"elapsed time (CaptureNetworkSpeed): {sw1.ElapsedMilliseconds} | time {DateTime.Now.ToString("O")}");
                    #endif
                    //Debug.WriteLine($"current thread (CaptureNetworkSpeed): {Thread.CurrentThread.ManagedThreadId}");
                    //Debug.WriteLine($"networkProcess {DownloadSpeed}");
                }
            }
            catch (OperationCanceledException ex)
            {
                Debug.WriteLine($"cancel speed token invoked: {ex.Message}");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Capture network speed error: {ex.Message}");
            }
        }

        private void Device_OnPacketArrival(object sender, PacketCapture e)
        {

            var rawPacket = e.GetPacket();
            var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
            var tcpPacket = packet.Extract<TcpPacket>();
            var ipPacket = packet.Extract<IPPacket>();

            if (tcpPacket != null)
            {
                ipPacket!.PayloadPacket = tcpPacket;
                ipPacket!.UpdateCalculatedValues();
                tcpPacket!.UpdateTcpChecksum();

                var srcIp = ipPacket!.SourceAddress;
                var dstIp = ipPacket!.DestinationAddress;
                var srcPort = tcpPacket.SourcePort;
                var dstPort = tcpPacket.DestinationPort;
                var packetLength = tcpPacket.PayloadData.Length;

                if (packetLength > 0)
                {
                    SendOrRecvPackets(srcIp, srcPort, dstIp, dstPort, packetLength);
                }

                //Console.WriteLine($"Captured Packet: {ipPacket.SourceAddress}:{tcpPacket.SourcePort} -> {ipPacket.DestinationAddress}:{tcpPacket.DestinationPort}, Payload Length: {tcpPacket.PayloadData.Length}");

            }
        }

        private void SendOrRecvPackets(IPAddress? srcIp, int srcPort, IPAddress? dstIp, int dstPort, int payloadLength)
        {
            bool ipCompSrc = ByteArray.Compare(srcIp.GetAddressBytes(), localIPv4);
            // bool ipCompDest = ByteArray.Compare(dstIp.GetAddressBytes(), localIPv4);

            if (ipCompSrc)
            {
                //If my Ip source is local Ip save destination data for processing
                SendPacket(dstIp, dstPort, payloadLength);
            }
            else
            {
                //save source data
                RecvPacket(srcIp, srcPort, payloadLength);
            }

        }

        private void RecvPacket(IPAddress? ip, int port, int size)
        {
            if (IsBufferTime)
            {
                lock (MyProcessesBuffer!)
                {
                    string ipStr = ip.ToString();
                    MyProcessesBuffer!.TryAdd(ipStr, new MyProcess_Small(ip, 0, 0, port));
                    MyProcessesBuffer[ipStr]!.CurrentDataRecv += size;
                }
            }
            else
            {
                lock (MyProcesses!)
                {
                    string ipStr = ip.ToString();
                    MyProcesses!.TryAdd(ipStr, new MyProcess_Small(ip, 0, 0, port));
                    MyProcesses[ipStr]!.CurrentDataRecv += size;
                }
            }
                
        }

        private void SendPacket(IPAddress? ip, int port, int size)
        {
            if (IsBufferTime)
            {
                lock (MyProcessesBuffer!)
                {
                    string ipStr = ip.ToString();
                    MyProcessesBuffer!.TryAdd(ipStr, new MyProcess_Small(ip, 0, 0, port));
                    MyProcessesBuffer[ipStr]!.CurrentDataSend += size;
                }
            }
            else
            {
                lock (MyProcesses!)
                {
                    string ipStr = ip.ToString();
                    MyProcesses!.TryAdd(ipStr, new MyProcess_Small(ip, 0, 0, port));
                    MyProcesses[ipStr]!.CurrentDataSend += size;
                }
            }
                
        }
        #endregion

        #region Cleanup
        public void Dispose()
        {
            throw new NotImplementedException();
        }
        #endregion

    }
}
