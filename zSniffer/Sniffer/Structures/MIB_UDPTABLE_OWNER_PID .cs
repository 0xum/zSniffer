﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;

[StructLayout ( LayoutKind.Sequential )]
public struct MIB_UDPTABLE_OWNER_PID {
    public uint dwNumEntries;
    public MIB_UDPROW_OWNER_PID udpTable;
}
