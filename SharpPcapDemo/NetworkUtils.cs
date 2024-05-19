using System;
using System.Net;
using System.Runtime.InteropServices;

public class NetworkUtils
{
    private const int AF_INET = 2;
    private const int AF_INET6 = 30;

    public static int GetProcessIdForConnectionMacOS(string localAddress, int localPort, string remoteAddress, int remotePort)
    {
        int bufferSize = 4096;
        IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
        int processId = -1;

        try
        {
            int numPids = Libproc.proc_listpids(Libproc.PROC_ALL_PIDS, 0, buffer, bufferSize);
            if (numPids <= 0)
            {
                Console.WriteLine("Error getting process IDs");
                return -1;
            }

            numPids /= sizeof(int);
            for (int i = 0; i < numPids; i++)
            {
                int pid = Marshal.ReadInt32(buffer, i * sizeof(int));
                if (CheckProcessForConnection(pid, localAddress, localPort, remoteAddress, remotePort))
                {
                    processId = pid;
                    break;
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return processId;
    }

    private static bool CheckProcessForConnection(int pid, string localAddress, int localPort, string remoteAddress, int remotePort)
    {
        int bufferSize = 4096;
        IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

        try
        {
            int numFds = Libproc.proc_pidinfo(pid, Libproc.PROC_PIDLISTFDS, 0, buffer, bufferSize);
            if (numFds <= 0)
            {
                return false;
            }

            numFds /= Marshal.SizeOf(typeof(Libproc.ProcFdInfo));
            for (int i = 0; i < numFds; i++)
            {
                Libproc.ProcFdInfo fdInfo = Marshal.PtrToStructure<Libproc.ProcFdInfo>(buffer + i * Marshal.SizeOf(typeof(Libproc.ProcFdInfo)));

                if (fdInfo.proc_fdtype == Libproc.PROC_PIDLISTFDS_SIZE)
                {
                    IntPtr socketBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Libproc.SocketFdInfo)));

                    try
                    {
                        int ret = Libproc.proc_pidfdinfo(pid, fdInfo.proc_fd, Libproc.PROC_PIDFDSOCKETINFO, socketBuffer, Marshal.SizeOf(typeof(Libproc.SocketFdInfo)));
                        if (ret != Marshal.SizeOf(typeof(Libproc.SocketFdInfo)))
                        {
                            continue;
                        }

                        Libproc.SocketFdInfo socketInfo = Marshal.PtrToStructure<Libproc.SocketFdInfo>(socketBuffer);

                        if (socketInfo.psi_soi_family == AF_INET || socketInfo.psi_soi_family == AF_INET6)
                        {
                            string socketLocalAddress = socketInfo.psi_soi_family == AF_INET
                                ? new IPAddress(BitConverter.GetBytes(socketInfo.psi.soi_proto.pri_tcp.tcpsi_ini.insi_laddr.i46a_addr4)).ToString()
                                : new IPAddress(socketInfo.psi.soi_proto.pri_tcp.tcpsi_ini.insi_laddr.i46a_addr6).ToString();

                            string socketRemoteAddress = socketInfo.psi_soi_family == AF_INET
                                ? new IPAddress(BitConverter.GetBytes(socketInfo.psi.soi_proto.pri_tcp.tcpsi_ini.insi_faddr.i46a_addr4)).ToString()
                                : new IPAddress(socketInfo.psi.soi_proto.pri_tcp.tcpsi_ini.insi_faddr.i46a_addr6).ToString();

                            int socketLocalPort = (int)socketInfo.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport;
                            int socketRemotePort = (int)socketInfo.psi.soi_proto.pri_tcp.tcpsi_ini.insi_fport;

                            if (socketLocalAddress == localAddress && socketLocalPort == localPort &&
                                socketRemoteAddress == remoteAddress && socketRemotePort == remotePort)
                            {
                                return true;
                            }
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(socketBuffer);
                    }
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return false;
    }
}
