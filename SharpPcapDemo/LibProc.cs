using System;
using System.Runtime.InteropServices;

class Libproc
{
    public const int PROC_PIDLISTFDS = 1;
    public const int PROC_PIDFDSOCKETINFO = 2;
    public const int PROC_ALL_PIDS = 1;
    public const int PROC_PIDLISTFDS_SIZE = 1024;

    [StructLayout(LayoutKind.Sequential)]
    public struct ProcFdInfo
    {
        public int proc_fd;
        public int proc_fdtype;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SocketFdInfo
    {
        public int psi_soi_family;
        public int psi_soi_type;
        public int psi_soi_protocol;
        public int psi_soi_pcb;
        public SocketInfo psi;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SocketInfo
    {
        public int soi_stat;
        public int soi_so;
        public int soi_pcb;
        public short soi_protocol;
        public int soi_type;
        public SocketAddress soi_proto;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SocketAddress
    {
        public TcpInfo pri_tcp;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TcpInfo
    {
        public TcpSockInfo tcpsi_ini;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TcpSockInfo
    {
        public InSockInfo insi_laddr;
        public InSockInfo insi_faddr;
        public ushort insi_lport;
        public ushort insi_fport;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct InSockInfo
    {
        public uint i46a_addr4;
        public byte[] i46a_addr6;
    }

    [DllImport("/usr/lib/libproc.dylib")]
    public static extern int proc_listpids(int type, int typeinfo, IntPtr buffer, int buffersize);

    [DllImport("/usr/lib/libproc.dylib")]
    public static extern int proc_pidinfo(int pid, int flavor, ulong arg, IntPtr buffer, int buffersize);

    [DllImport("/usr/lib/libproc.dylib")]
    public static extern int proc_pidfdinfo(int pid, int fd, int flavor, IntPtr buffer, int buffersize);
}
