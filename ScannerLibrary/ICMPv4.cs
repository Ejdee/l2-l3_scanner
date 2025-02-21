using System.Net;
using System.Net.NetworkInformation;

namespace ScannerLibrary;

public class IcmpV4
{
    public bool IcmpPing(IPAddress address)
    {
        Ping ping = new Ping();
        PingReply reply = ping.Send(address);
        return reply.Status == IPStatus.Success;
    }    
}