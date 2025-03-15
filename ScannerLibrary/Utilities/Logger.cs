using System.Net;

namespace ScannerLibrary.Utilities;

public class Logger
{
    public void PrintResult(IReadOnlyDictionary<IPAddress, ScanResult> results, IEnumerable<String> subnets)
    {
        var sortedIps = new IpUtility().GetIpAddresses(subnets);
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
}