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
        
        await scanManager.ScanAsync(
            parser.ParsedOptions.Interface,
            parser.ParsedOptions.Wait,
            parser.ParsedOptions.Subnets);
    }
}