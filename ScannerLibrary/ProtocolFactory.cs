using ScannerLibrary.Interfaces;
using ScannerLibrary.Protocols;
using ScannerLibrary.Utilities;

namespace ScannerLibrary;

public class ProtocolFactory
{
    public static IProtocol GetProtocol(ProtocolTypes protocolType)
    {
        return protocolType switch
        {
            ProtocolTypes.Arp => new Arp(),
            ProtocolTypes.Icmpv4 => new IcmpV4(),
            ProtocolTypes.Icmpv6 => new IcmpV6(),
            ProtocolTypes.Ndp => new Ndp(new IpUtility()),
            _ => throw new ArgumentException("Invalid protocol type")
        };
    }
}