﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Diagnostics;

public class TcpRecordPid {
    private int PLength { get; set; }
    public IPAddress LocalAddress { get; set; }
    public IPAddress RemoteAddress { get; set; }
    public ushort LocalPort { get; set; }
    public ushort RemotePort { get; set; }
    public int PID { get; set; }
    public uint State { get; set; }
    public string Protocol { get; set; }
    public int Hash { get { return GetHashCode(); } }
    public string ProcessName {
        get {
            if (PID == 0)
                return "System";
            Process p;
            if ((p = FindProcessByPid(PID)) != null)
                return p.ProcessName;
            return "Unknown";
        }
    }
    public static Process FindProcessByPid(int pid) {
        return Process.GetProcesses().Where(p => p.Id == pid).SingleOrDefault();
    }
    public TcpRecordPid(IPAddress localIP, IPAddress remoteIP, ushort localPort, ushort remotePort, int pid, uint state) {
        LocalAddress = localIP;
        RemoteAddress = remoteIP;
        LocalPort = localPort;
        RemotePort = remotePort;
        PID = pid;
        State = state;
        Protocol = "TCP";
        PLength = 65535;
    }

    public override bool Equals(object obj) {
        if (obj != null)
            if (obj is TcpRecordPid)
                if (((TcpRecordPid)obj).GetHashCode() == this.GetHashCode())
                    return true;
        return false;
    }
}
