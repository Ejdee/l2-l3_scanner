using CommandLine;

namespace ScannerLibrary
{
    /// <summary>
    /// Specification of valid argument options for Parser.
    /// </summary>
    public class Options
    {
        [Option('i', "interface", Required = false, HelpText = "Interface to scan through")]
        public string Interface { get; set; } = string.Empty;
        
        [Option('w', "wait", Required = false, Default = 5000, HelpText = "timeout in milliseconds to wait for a \"" +
                                                          "response for a single port scan.")]
        public int Wait { get; set; }

        [Option('s', "subnet", Required = false, HelpText = "Segments to scan using IPv4 or IPv6 \"" +
                                                            "address. There can be multiple segments to be scanned.")]
        public IEnumerable<string> Subnets { get; set; } = [];
    }
}

