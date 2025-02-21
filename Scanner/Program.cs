using System.Net;
using ScannerLibrary;

namespace Scanner;

abstract class Program
{
    public static void Main(string[] args)
    {
        ArgumentParser parser = new ArgumentParser();
        parser.Parse(args);

        //Dictionary<IPAddress, (bool, string, bool)> results;
        IpHandler ipHandler = new IpHandler();
        
        IcmpV4 ping = new IcmpV4();
        bool result = ping.IcmpPing(IPAddress.Parse("8.8.8.8"));
        Console.WriteLine(result ? "ICMP OK" : "ICMP FAIL");
        
        parser.PrintResults(parser, ipHandler);
    }
}