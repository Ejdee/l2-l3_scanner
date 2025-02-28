using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using ScannerLibrary;
using SharpPcap.LibPcap;

namespace Scanner;

internal abstract class Program
{
    private static async Task Main(string[] args)
    {
        Logger logger = new Logger();
        LibPcapLiveDeviceList deviceList = LibPcapLiveDeviceList.Instance;
        
        ArgumentParser parser = new ArgumentParser();
        parser.Parse(args);

        
        if (string.IsNullOrEmpty(parser.ParsedOptions.Interface))
        {
            Logger.PrintAvailableInterfaces(deviceList);
            return;
        }
        
        string interfaceName = parser.ParsedOptions.Interface;
        
        int waitTimeout = parser.ParsedOptions.Wait;
        
        var sourceIps = logger.GetSourceAddresses(deviceList, interfaceName);

        foreach (var sourceIp in sourceIps)
        {
            Console.WriteLine("INTERFACE : " + interfaceName + "  -   source : " + sourceIp);
        }

        IpHandler ipHandler = new IpHandler();

        List<IPAddress> hosts = new List<IPAddress>();
        Debug.Assert(parser.ParsedOptions != null, "parser.ParsedOptions != null");
        
        // Iterate through the subnets specified in the program arguments
        foreach (string address in parser.ParsedOptions.Subnets)
        {
            hosts.AddRange(ipHandler.IterateAndPrintHostIp(address));
        }

        var ipStatus = new ConcurrentDictionary<IPAddress, IpAddressInfo>();
        foreach (IPAddress host in hosts)
        {
            ipStatus[host] = new IpAddressInfo { ArpSuccess = false, MacAddress = "", IcmpReply = false };
        }

        var device = deviceList.FirstOrDefault(dev => dev.Name == interfaceName);
        if (device == null)
        {
            Console.WriteLine("No interface found with interface name " + interfaceName);
            return;
        }
        
        IcmpV4 icmpInst = new IcmpV4();
        Arp arpInst = new Arp();
        Console.WriteLine("Sending from interface: " + device.Name);

        var icmpv6Inst = new IcmpV6();
        var ndpInst = new Ndp();
        
        
        NetworkScanner scanner = new NetworkScanner(icmpInst, arpInst, device, icmpv6Inst, ndpInst); 
        await scanner.ScanNetwork(sourceIps[0], sourceIps[1], ipStatus, waitTimeout);
        
        Console.WriteLine();
        Console.WriteLine("****************************************");
        logger.PrintResult(ipStatus, hosts);
        Console.WriteLine("****************************************");
    }
}