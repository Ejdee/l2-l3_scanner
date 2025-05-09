using CommandLine;

namespace ScannerLibrary.CLI
{
    public class ArgumentParser
    {
        public ArgumentOptions? ParsedOptions { get; private set; }
        
        /// <summary>
        /// Parse command-line arguments. Call RunOptions() on success and HandleParserError() on failure.
        /// </summary>
        public void Parse(string[] args)
        {
            // New parser instance that allows multiple occurrences of the same argument (it is needed for -s)
            Parser parser = new Parser(settings => settings.AllowMultiInstance = true);
            
            parser.ParseArguments<ArgumentOptions>(args)
                .WithParsed(RunOptions)
                .WithNotParsed(HandleParseError);
        }

        private void RunOptions(ArgumentOptions? opts)
        {
            ParsedOptions = opts;
        }

        private static void HandleParseError(IEnumerable<Error> errs)
        {
            Console.WriteLine("Parsing arguments failed.");
            for (int i = 0; i < errs.Count(); i++)
            {
                Console.WriteLine(errs.ElementAt(i));
            }
        }
    }
}