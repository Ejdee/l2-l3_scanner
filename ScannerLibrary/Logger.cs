using SharpPcap.LibPcap;

namespace ScannerLibrary;

public class Logger
{
    public void ListActiveInterfaces(LibPcapLiveDeviceList deviceList)
    {
        Console.WriteLine("Available interfaces:");
        foreach (LibPcapLiveDevice liveDevice in deviceList)
        {
            if (liveDevice.Addresses.Count > 0)
            {
                Console.WriteLine("\t" + liveDevice.Name);
            }
        } 
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
                int hosts = ipHandler.GetNumberOfHosts(subnet);
                Console.Write($" - {hosts} hosts");
                Console.WriteLine();
            }
        }
    } 
}