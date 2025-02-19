using ScannerLibrary;

namespace Scanner;

abstract class Program
{
    public static void Main(string[] args)
    {
        ArgumentParser parser = new ArgumentParser();
        parser.Parse(args);
        
        if (parser.ParsedOptions != null)
        {
            Console.WriteLine("Interface - " + parser.ParsedOptions.Interface);
            Console.WriteLine("Wait - " + parser.ParsedOptions.Wait);
            Console.Write("Subnets - ");
            foreach (var subnet in parser.ParsedOptions.Subnets)
            {
                Console.Write(subnet + " "); 
            }
            Console.WriteLine();
        }
    }
}