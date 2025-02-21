using System.Diagnostics;
using System.Net;
using System.Text.RegularExpressions;
using ScannerLibrary;
using SharpPcap;
using SharpPcap.LibPcap;

namespace Scanner;

abstract class Program
{
    public static void Main(string[] args)
    {
        Logger logger = new Logger();
        LibPcapLiveDeviceList deviceList = LibPcapLiveDeviceList.Instance;
        logger.ListActiveInterfaces(deviceList);

        ArgumentParser parser = new ArgumentParser();
        parser.Parse(args);

        //Dictionary<IPAddress, (bool, string, bool)> results;
        IpHandler ipHandler = new IpHandler();

        List<IPAddress> hosts = new List<IPAddress>();
        Debug.Assert(parser.ParsedOptions != null, "parser.ParsedOptions != null");
        foreach (string address in parser.ParsedOptions.Subnets)
        {
            hosts.AddRange(ipHandler.IterateAndPrintHostIp(address));
        }
        
        IcmpV4 ping = new IcmpV4();
        bool result = ping.IcmpPing(IPAddress.Parse("8.8.8.8"));
        Console.WriteLine(result ? "ICMP OK" : "ICMP FAIL");
        
        logger.PrintParsedResults(parser, ipHandler);
    }
}