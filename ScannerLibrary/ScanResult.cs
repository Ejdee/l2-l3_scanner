namespace ScannerLibrary;

public class ScanResult
{
    public bool IcmpReply { get; set; }
    public required string MacAddress { get; set; }
    public bool ArpSuccess { get; set; }   
}