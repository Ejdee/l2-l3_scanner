using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using ScannerLibrary;
using SharpPcap;
using SharpPcap.LibPcap;

namespace Scanner;

internal abstract class Program
{
    private static async Task Main(string[] args)
    {
        foreach (NetworkInterface networkInterface in NetworkInterface.GetAllNetworkInterfaces())
        {
            Console.WriteLine($"Interface: {networkInterface.Name}");
            
            foreach (UnicastIPAddressInformation ipAddressInfo in networkInterface.GetIPProperties().UnicastAddresses)
            {
                if (ipAddressInfo.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                {
                    Console.WriteLine($"  IPv6 Address: {ipAddressInfo.Address}");
                } else if (ipAddressInfo.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    Console.WriteLine($"  IPv4 Address: {ipAddressInfo.Address}");
                }
            }
        }
        
        
        
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

        var icmpv6Inst = new IcmpV6();
        IPAddress sourceIp = IPAddress.Parse("fe80::d38e:f7ee:3f82:8a90%wlp2s0");
        IPAddress destIp = IPAddress.Parse("2a02:8308:a18b:3500::a199");
        icmpv6Inst.SendIcmpv6Packet(sourceIp, destIp);

        var ndpInst = new Ndp();
        device.Open();
        ndpInst.SendNdpRequest(sourceIp, destIp, device);
        device.Close();
        
        
        //NetworkScanner scanner = new NetworkScanner(icmpInst, arpInst, device, icmpv6Inst); 
        //await scanner.ScanNetwork(source, ipStatus);
        
        logger.PrintParsedResults(parser, ipHandler);
        Console.WriteLine();
        Console.WriteLine("****************************************");
        logger.PrintResult(ipStatus);
        Console.WriteLine("****************************************");
    }
}