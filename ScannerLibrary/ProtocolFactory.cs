using ScannerLibrary.Interfaces;
using ScannerLibrary.Protocols;
using ScannerLibrary.Utilities;

namespace ScannerLibrary;

public class ProtocolFactory
{
    public static IProtocol GetProtocol(ProtocolTypes protocolType)
    {
        var ipUtility = new IpUtility(); 
        var checksumUtility = new ChecksumUtility();
        
        return protocolType switch
        {
            ProtocolTypes.Arp => new Arp(),
            ProtocolTypes.Icmpv4 => new IcmpV4(checksumUtility),
            ProtocolTypes.Icmpv6 => new IcmpV6(checksumUtility),
            ProtocolTypes.Ndp => new Ndp(ipUtility, checksumUtility),
            _ => throw new ArgumentException("Invalid protocol type")
        };
    }
}