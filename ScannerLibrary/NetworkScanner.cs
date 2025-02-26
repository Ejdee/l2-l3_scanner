using System.Net;
using System.Reflection.Metadata;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace ScannerLibrary;

public class NetworkScanner
{
    private readonly IcmpV4 _icmp;
    private readonly Arp _arp;
    private readonly LibPcapLiveDevice _device;

    public NetworkScanner(IcmpV4 icmp, Arp arp, LibPcapLiveDevice device)
    {
        _icmp = icmp;
        _arp = arp;
        _device = device;
    }
    
    /// <summary>
    /// Set up new thread for sniffing for replies and send the requests.
    /// </summary>
    public async Task ScanNetwork(IPAddress source, Dictionary<IPAddress, IpAddressInfo> destinations)
    {
        _device.Open(DeviceModes.Promiscuous);

        var listenerTask = Task.Run(() => PacketListener(destinations)); 
        
        SendArpRequests(destinations, source);
        
        await Task.Delay(5000);
        
        SendIcmpRequests(destinations, source);
        
        await Task.Delay(5000);

        _device.StopCapture();
        _device.Close();
        await listenerTask;
    }

    /// <summary>
    /// Unpack packet on arrival and check if it is ICMP reply.
    /// </summary>
    private void PacketListener(Dictionary<IPAddress, IpAddressInfo> dict)
    {
        _device.OnPacketArrival += (sender, e) =>
        {
            var rawPacket = Packet.ParsePacket(e.GetPacket().LinkLayerType, e.GetPacket().Data);
            var ipPacket = rawPacket.Extract<IPPacket>();
            var icmpPacket = rawPacket.Extract<IcmpV4Packet>();

            if (icmpPacket != null && icmpPacket.TypeCode == IcmpV4TypeCode.EchoReply)
            {
                dict[ipPacket.SourceAddress].IcmpReply = true;
                Console.WriteLine("Received icmp packet from: " + ipPacket.SourceAddress);
            }
            
            var arpPacket = rawPacket.Extract<ArpPacket>();
            if (arpPacket != null && arpPacket.Operation == ArpOperation.Response)
            {
                var senderIp = arpPacket.SenderProtocolAddress;
                dict[senderIp].ArpSuccess = true;
                dict[senderIp].MacAddress = arpPacket.SenderHardwareAddress.ToString();
                Console.WriteLine("Received arp packet from: " + senderIp);
            }
        };
        
        Console.WriteLine();
        Console.WriteLine("-- Listening for replies...");
        
        _device.StartCapture();
    }
    
    private void SendArpRequests(Dictionary<IPAddress, IpAddressInfo> destinations, IPAddress source)
    {
        foreach (var destination in destinations.Keys)
        {
            _arp.SendArpRequest(destination, source, _device);
        }
    }

    private void SendIcmpRequests(Dictionary<IPAddress, IpAddressInfo> destinations, IPAddress source)
    {
        foreach (var destination in destinations)
        {
            if (destination.Value.MacAddress == "")
            {
                continue;
            }
            _icmp.SendIcmpPacket(source, destination.Key);
        }
    }
}