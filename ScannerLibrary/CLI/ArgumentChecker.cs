using ScannerLibrary.Utilities;

namespace ScannerLibrary.CLI;

public class ArgumentChecker
{
    public void CheckArguments(string[] args, ArgumentParser parser) 
    {
        // if there is help specified, print help and exit without further checks
        if (parser.ParsedOptions!.Help)
        {
            new Logger().PrintHelp();
            Environment.Exit(0);
        }
         
        if (args.Count(a => a is "-i" or "--interface") > 1)
        {
            Console.Error.WriteLine("Invalid arguments. Use -h or --help for help.");
            Environment.Exit(1);
        } 
        if (args.Count(a => a is "-w" or "--wait") > 1)
        {
            Console.Error.WriteLine("Invalid arguments. Use -h or --help for help.");
            Environment.Exit(1);
        }
        if (args.Count(a => a is "-s" or "--subnet") == 0)
        {
            Console.Error.WriteLine("Invalid arguments. Use -h or --help for help.");
            Environment.Exit(1);
        }
    }
    
    private bool InterfaceSpecified(string[] args) => args.Any(a => a is "-i" or "--interface");
    private bool WaitSpecified(string[] args) => args.Any(a => a is "-w" or "--wait");
    private bool SubnetSpecified(string[] args) => args.Any(a => a is "-s" or "--subnet");

    public bool ArgumentsSpecified(string[] args)
    {   
        return InterfaceSpecified(args) || WaitSpecified(args) || SubnetSpecified(args);
    }

    public bool PrintInterfaces(string[] args, ArgumentParser parser)
    {
        return !ArgumentsSpecified(args) || (InterfaceSpecified(args) && parser.ParsedOptions!.Interface == string.Empty && !WaitSpecified(args) && !SubnetSpecified(args));
    }
}