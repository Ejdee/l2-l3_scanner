using System.Diagnostics;
using System.Net;
using System.Text.RegularExpressions;
using ScannerLibrary;
using SharpPcap;
using SharpPcap.LibPcap;

namespace Scanner;

internal abstract class Program
{
    private static async Task Main(string[] args)
    {
        Logger logger = new Logger();
        LibPcapLiveDeviceList deviceList = LibPcapLiveDeviceList.Instance;
        IPAddress source = logger.ListActiveInterfaces(deviceList);

        ArgumentParser parser = new ArgumentParser();
        parser.Parse(args);

        //Dictionary<IPAddress, (bool, string, bool)> results;
        IpHandler ipHandler = new IpHandler();

        List<IPAddress> hosts = new List<IPAddress>();
        Debug.Assert(parser.ParsedOptions != null, "parser.ParsedOptions != null");
        
        // Iterate through the subnets specified in the program arguments
        foreach (string address in parser.ParsedOptions.Subnets)
        {
            hosts.AddRange(ipHandler.IterateAndPrintHostIp(address));
        }

        var ipStatus = new Dictionary<IPAddress, IpAddressInfo>();
        foreach (IPAddress host in hosts)
        {
            ipStatus[host] = new IpAddressInfo { ArpSuccess = false, MacAddress = "", IcmpReply = false };
        }

        using var device = deviceList.First();
        IcmpV4 icmpInst = new IcmpV4();
        Arp arpInst = new Arp();
        Console.WriteLine("Sending from interface: " + device.Name);

        NetworkScanner scanner = new NetworkScanner(icmpInst, arpInst, device); 
        await scanner.ScanNetwork(source, ipStatus);
        
        logger.PrintParsedResults(parser, ipHandler);
        Console.WriteLine();
        Console.WriteLine("****************************************");
        logger.PrintResult(ipStatus);
        Console.WriteLine("****************************************");
    }
}