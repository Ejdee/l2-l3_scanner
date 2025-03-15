using System.Diagnostics;
using ScannerLibrary;
using ScannerLibrary.CLI;
using ScannerLibrary.ScannerCore;

namespace Scanner;

internal abstract class Program
{
    private static async Task Main(string[] args)
    {
        ArgumentParser parser = new ArgumentParser();
        parser.Parse(args);

        var scanManager = new ScanManager();
        
        Debug.Assert(parser.ParsedOptions != null, "parser.ParsedOptions != null");
        await scanManager.ScanAsync(
            parser.ParsedOptions.Interface,
            parser.ParsedOptions.Wait,
            parser.ParsedOptions.Subnets);
    }
}