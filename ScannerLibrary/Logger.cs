using System.Collections.Concurrent;
using System.Net;
using SharpPcap.LibPcap;

namespace ScannerLibrary;

public class Logger
{
    public List<IPAddress> GetSourceAddresses(LibPcapLiveDeviceList deviceList, string interfaceName)
    {
        List<IPAddress> sourcesIp = new List<IPAddress>();
        foreach (LibPcapLiveDevice liveDevice in deviceList)
        {
            if (liveDevice.Addresses.Count <= 0)
            {
                continue;
            }

            if (liveDevice.Name == interfaceName)
            {
                foreach (PcapAddress addr in liveDevice.Addresses)
                {
                    if (addr.Addr != null && 
                        addr.Addr.ipAddress != null && 
                        addr.Addr.ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        sourcesIp.Add(addr.Addr.ipAddress);
                    } else if (addr.Addr is { ipAddress.AddressFamily: System.Net.Sockets.AddressFamily.InterNetworkV6 })
                    {
                        if(addr.Addr.ipAddress.ToString().StartsWith("fe80")) sourcesIp.Add(addr.Addr.ipAddress);
                    }
                }

                break;
            }
        }

        return sourcesIp;
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

    public void PrintResult(ConcurrentDictionary<IPAddress, IpAddressInfo> results, List<IPAddress> sortedIps)
    {
        foreach (var ip in sortedIps)
        {
            if (results[ip].IcmpReply)
            {
                Console.WriteLine("\u001b[38;5;46m{0} \t - ICMP: {1} \t ARP: {2} \t MAC: {3}\u001b[0m", ip, results[ip].IcmpReply, results[ip].ArpSuccess, results[ip].MacAddress);
            } else if (!results[ip].IcmpReply && !results[ip].ArpSuccess)
            {
                Console.WriteLine("\u001b[38;5;196m{0} \t - ICMP: {1} \t ARP: {2} \t MAC: {3}\u001b[0m", ip, results[ip].IcmpReply, results[ip].ArpSuccess, results[ip].MacAddress);
            } else if (!results[ip].IcmpReply && results[ip].ArpSuccess)
            {
                Console.WriteLine("\u001b[38;5;226m{0} \t - ICMP: {1} \t ARP: {2} \t MAC: {3}\u001b[0m", ip, results[ip].IcmpReply, results[ip].ArpSuccess, results[ip].MacAddress);
            }
        }
    }

    public static void PrintAvailableInterfaces(LibPcapLiveDeviceList deviceList)
    {
        Console.WriteLine("Available Interfaces"); 
        foreach (LibPcapLiveDevice liveDevice in deviceList)
        {
            if (liveDevice.Addresses.Count <= 0)
            {
                continue;
            }
            
            Console.WriteLine("\t Name: " + liveDevice.Name);
            
            foreach (PcapAddress addr in liveDevice.Addresses)
            {
                if (addr.Addr != null && 
                    addr.Addr.ipAddress != null && 
                    addr.Addr.ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    Console.WriteLine("\t \t IPv4 : " + addr.Addr.ipAddress);
                } else if (addr.Addr is { ipAddress.AddressFamily: System.Net.Sockets.AddressFamily.InterNetworkV6 })
                {
                    Console.WriteLine("\t \t IPv6 : " + addr.Addr.ipAddress);
                }
            }

            break;
        }
    }
}