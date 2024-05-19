using System;
using System.Collections.Generic;
using System.Linq;

public class ConnectionInfo
{
    public string SourceIp { get; set; }
    public int SourcePort { get; set; }
    public string DestinationIp { get; set; }
    public int DestinationPort { get; set; }
    public int ProcessId { get; set; }
}

public class ConnectionStore
{
    private List<ConnectionInfo> connections = new List<ConnectionInfo>();

    public void AddConnection(ConnectionInfo connection)
    {
        connections.Add(connection);
    }

    public int GetProcessId(string srcIp, int srcPort, string dstIp, int dstPort)
    {
        var connection = connections.FirstOrDefault(c =>
            c.SourceIp == srcIp &&
            c.SourcePort == srcPort &&
            c.DestinationIp == dstIp &&
            c.DestinationPort == dstPort);

        return connection != null ? connection.ProcessId : -1;
    }
}