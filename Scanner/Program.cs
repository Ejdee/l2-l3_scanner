using System.Diagnostics;
using ScannerLibrary;
using ScannerLibrary.CLI;
using ScannerLibrary.ScannerCore;
using ScannerLibrary.Utilities;

namespace Scanner;

internal abstract class Program
{
    private static async Task Main(string[] args)
    {
        ArgumentParser parser = new ArgumentParser();
        
        if(args.Contains("--help") || args.Contains("-h"))
        {
            new Logger().PrintHelp();
            Environment.Exit(0);
        }
        
        parser.Parse(args);

        var scanManager = new ScanManager();
        
        Debug.Assert(parser.ParsedOptions != null, "parser.ParsedOptions != null");
        
        var argChecker = new ArgumentChecker();
        argChecker.CheckArguments(args, parser);

        if (argChecker.PrintInterfaces(args, parser))
        {
            scanManager.ScanInterfaces();
            Environment.Exit(2);
        }

        try
        {
            await scanManager.ScanAsync(
                parser.ParsedOptions.Interface,
                parser.ParsedOptions.Wait,
                parser.ParsedOptions.Subnets);
        }
        catch (InvalidOperationException e)
        {
            await Console.Error.WriteLineAsync(e.Message);
            Environment.Exit(1);
        }
        catch (Exception e)
        {
            Console.Error.WriteLine(e);
            Environment.Exit(1);
        }
    }
}