using System.Net;
using ScannerLibrary;

namespace Scanner;

abstract class Program
{
    public static void Main(string[] args)
    {
        ArgumentParser parser = new ArgumentParser();
        parser.Parse(args);
        
        IpHandler ipHandler = new IpHandler();
        
        if (parser.ParsedOptions != null)
        {
            Console.WriteLine("Interface - " + parser.ParsedOptions.Interface);
            Console.WriteLine("Wait - " + parser.ParsedOptions.Wait);
            Console.WriteLine("Subnets - ");
            foreach (var subnet in parser.ParsedOptions.Subnets)
            {
                Console.WriteLine(subnet + " "); 
                int hosts = ipHandler.GetNumberOfHosts(subnet);
                Console.Write($" - {hosts} hosts");
                Console.WriteLine();
            }
        }
    }
}