using System.Net;
using System.Net.Sockets;

namespace ScannerLibrary.Utilities;

public class Logger
{
    private readonly IpUtility _ipUtility = new IpUtility();
    public void PrintResult(IReadOnlyDictionary<IPAddress, ScanResult> results, IEnumerable<String> subnets)
    {
        var sortedIps = _ipUtility.GetIpAddresses(subnets);
        
        // Print the ranges
        Console.WriteLine("Scanning ranges:");
        foreach (var subnet in subnets)
        {
            Console.WriteLine(subnet + " " + _ipUtility.GetNumberOfHosts(subnet));
        }
        
        // Print the blank line
        Console.WriteLine();
        
        // Print the results
        foreach (var ip in sortedIps)
        {
            if (ip.AddressFamily == AddressFamily.InterNetwork)
            {
                Console.Write(ip + " ");
                if (results[ip].ArpSuccess)
                {
                    Console.Write("arp OK ({0}), ", results[ip].MacAddress.ToLower());
                }
                else
                {
                    Console.Write("arp FAIL, ");
                }
                
                if (results[ip].IcmpReply)
                {
                    Console.WriteLine("icmpv4 OK");
                }
                else
                {
                    Console.WriteLine("icmpv4 FAIL");
                }
            } else if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            {
                Console.Write(ip + " ");
                if (results[ip].ArpSuccess)
                {
                    Console.Write("ndp OK ({0}), ", results[ip].MacAddress.ToLower());
                }
                else
                {
                    Console.Write("ndp FAIL, ");
                }
                
                if (results[ip].IcmpReply)
                {
                    Console.WriteLine("icmpv6 OK");
                }
                else
                {
                    Console.WriteLine("icmpv6 FAIL");
                }
                
            }
            
            //if (results[ip].IcmpReply)
            //{
            //    Console.WriteLine("\u001b[38;5;46m{0} \t - ICMP: {1} \t ARP: {2} \t MAC: {3}\u001b[0m", ip, results[ip].IcmpReply, results[ip].ArpSuccess, results[ip].MacAddress);
            //} else if (!results[ip].IcmpReply && !results[ip].ArpSuccess)
            //{
            //    Console.WriteLine("\u001b[38;5;196m{0} \t - ICMP: {1} \t ARP: {2} \t MAC: {3}\u001b[0m", ip, results[ip].IcmpReply, results[ip].ArpSuccess, results[ip].MacAddress);
            //} else if (!results[ip].IcmpReply && results[ip].ArpSuccess)
            //{
            //    Console.WriteLine("\u001b[38;5;226m{0} \t - ICMP: {1} \t ARP: {2} \t MAC: {3}\u001b[0m", ip, results[ip].IcmpReply, results[ip].ArpSuccess, results[ip].MacAddress);
            //}
        }
    }

    public void PrintHelp()
    {
        Console.WriteLine("Usage: ./ipk-l2l3-scan {-h} [-i interface | --interface interface] {-w timeout} [-s ipv4-subnet | -s ipv6-subnet | --subnet ipv4-subnet | --subnet ipv6-subnet]");
        Console.WriteLine("Options:");
        Console.WriteLine("  -s, --subnet <subnet>          IPv4 or IPv6 subnet to scan. There can be multiple subnets to be scanned.");
        Console.WriteLine("  -i, --interface <interface>    One interface to scan through. If this parameter is not specified (and any other parameters as well)");
        Console.WriteLine("                                 or if only -i/--interface is specified without a value (and any other parameters are unspecified), a list of active interfaces is printed.");
        Console.WriteLine("  -w, --timeout <timeout>        Timeout in milliseconds to wait for responses.");
        Console.WriteLine("  -h, --help                     Display this help message");
    }
}