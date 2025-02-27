using System.Net;
using SharpPcap.LibPcap;

namespace ScannerLibrary;

public class Logger
{
    public IPAddress ListActiveInterfaces(LibPcapLiveDeviceList deviceList)
    {
        Console.WriteLine("Available interfaces:");
        foreach (LibPcapLiveDevice liveDevice in deviceList)
        {
            if (liveDevice.Addresses.Count > 0)
            {
                Console.WriteLine("\t" + liveDevice.Name);
            }
            
            foreach (PcapAddress addr in liveDevice.Addresses)
            {
                if (addr.Addr != null && 
                    addr.Addr.ipAddress != null && 
                    addr.Addr.ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    Console.WriteLine("\tIPv4 Address: " + addr.Addr.ipAddress);
                    return addr.Addr.ipAddress;
                }
            }
        }
        return null;
    }
    
    public void PrintParsedResults(ArgumentParser parser, IpHandler ipHandler)
    {
        if (parser.ParsedOptions != null)
        {
            Console.WriteLine("Interface - " + parser.ParsedOptions.Interface);
            Console.WriteLine("Wait - " + parser.ParsedOptions.Wait);
            Console.WriteLine("Subnets - ");
            foreach (var subnet in parser.ParsedOptions.Subnets)
            {
                Console.WriteLine(subnet + " "); 
                int hosts = IpHandler.GetNumberOfHosts(subnet);
                Console.Write($" - {hosts} hosts");
                Console.WriteLine();
            }
        }
    }

    public void PrintResult(Dictionary<IPAddress, IpAddressInfo> results)
    {
        foreach (KeyValuePair<IPAddress, IpAddressInfo> result in results)
        {
            Console.WriteLine("{0} - icmp: {1}  -  mac: {2}  -  arp: {3}", result.Key, result.Value.IcmpReply,
                result.Value.MacAddress, result.Value.ArpSuccess);
        }
    }
}