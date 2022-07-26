﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Diagnostics;


public class UdpRecordPid {
    private int PLength { get; set; }
    public IPAddress LocalAddress { get; set; }
    public uint LocalPort { get; set; }
    public int PID { get; set; }
    public string Protocol { get; set; }
    public string ProcessName {
        get {
            if ( PID == 0 )
                return "System";
            Process p;
            if ( ( p = ProcessInformation.FindProcessByPid ( PID ) ) != null )
                return p.ProcessName;
            return "Unknown";
        }
    }


    public UdpRecordPid ( ) {
    }

    public UdpRecordPid ( IPAddress localAddress, uint localPort, int pid ) {
        LocalAddress = localAddress;
        LocalPort = localPort;
        PID = pid;
        Protocol = "UDP";
        PLength = 65535;
    }
}
