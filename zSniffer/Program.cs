using System;
using System.Linq;
using System.Drawing;
using System.Threading;
using System.Diagnostics;

using CommandLine;

using Console = Colorful.Console;

namespace zSniffer
{
    public static class Program
    {
        class Options
        {
            [Option ( 'p', "target", Required = true, HelpText = "Target process to sniff." )]
            public string TargetName { get; set; }

            [Option ( 'm', "method", Required = true, HelpText = "Which protocol will be used. (TCP/UDP/ALL)" )]
            public string TargetMethod { get; set; }
        }

        static void Main ( string [ ] args )
        {
            Parser.Default.ParseArguments<Options> ( args )
                   .WithParsed<Options> ( o =>
                   {
                       var processes = Process.GetProcessesByName ( o.TargetName ).Length;

                       if ( processes == 0 )
                       {
                           Console.WriteLine ( "Cannot find process.", Color.Red );
                           Environment.Exit ( 0 );
                       }
                       else
                       {
                           switch ( o.TargetMethod.ToLower ( ) )
                           {
                               case "tcp":
                                   SniffTcp ( o.TargetName );
                                   break;

                               case "udp":
                                   SniffUdp ( o.TargetName );
                                   break;
                               case "all":
                                   SniffTcp ( o.TargetName );
                                   SniffUdp ( o.TargetName );
                                   break;

                               default: Console.WriteLine ( "Invalid protocol, use TCP, UDP or ALL.", Color.Red ); break;
                           }
                       }
                   } );
        }
        static void SniffTcp ( string targetProcess )
        {
            while ( true )
            {
                var process = Process.GetProcessesByName ( targetProcess ).FirstOrDefault();

                if ( process is null || process.HasExited )
                {
                    Console.WriteLine ( "Process exited.", Color.Red );
                    break;
                }
                else
                {
                    NetworkStatisticData.GetAllTcpConnections ( )
                                        .Where ( x => x.ProcessName == targetProcess )
                                        .ToList ( )
                                        .ForEach ( x =>
                                        {
                                            LogConnection ( process, x.RemoteAddress.ToString ( ), x.RemotePort.ToString ( ), "TCP" );
                                            Thread.Sleep ( 50 );
                                        } );
                }
            }
        }
        static void SniffUdp ( string targetProcess )
        {
            while ( true )
            {
                var process = Process.GetProcessesByName ( targetProcess ).FirstOrDefault();

                if ( process is null || process.HasExited )
                {
                    Console.WriteLine ( "Process exited.", Color.Red );
                    break;
                }
                else
                {
                    NetworkStatisticData.GetAllUdpConnections ( )
                    .Where ( x => x.ProcessName == targetProcess )
                    .ToList ( )
                    .ForEach ( x =>
                    {
                        LogConnection ( process, x.LocalAddress.ToString ( ), x.LocalPort.ToString ( ), "UDP" );
                        Thread.Sleep ( 50 );
                    } );
                }
            }
        }
        static void LogConnection ( Process p, string address, string port, string protocol )
        {
            Console.Title = $"[ zSniffer ] [ {p.ProcessName}:{p.Id} ]  [ {protocol} ] [ {address}:{port} ]";

            Console.Write ( "[" );
            Console.Write ( " zSniffer ", Color.Magenta );
            Console.Write ( "]" );

            Console.Write ( " " );

            Console.Write ( "[ " );
            Console.Write ( p.ProcessName );
            Console.Write ( ":" );
            Console.Write ( p.Id, Color.Gray );
            Console.Write ( " ]" );

            Console.Write ( " " );

            Console.Write ( "[ " );
            Console.Write ( protocol, Color.Green );
            Console.Write ( " ]" );

            Console.Write ( " " );

            Console.Write ( address, Color.Green );
            Console.Write ( ":" );
            Console.Write ( port, Color.LimeGreen );

            Console.Write ( "\n" );
        }

    }
}
