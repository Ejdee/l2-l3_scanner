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
}