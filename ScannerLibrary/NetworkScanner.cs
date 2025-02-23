using System.Net;
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

    private void SendPackets(Dictionary<IPAddress, IpAddressInfo> destinations, IPAddress source)
    {
        foreach (var destination in destinations.Keys)
        {
            _icmp.SendIcmpPacket(source, destination, _device);
            _arp.SendArpRequest(destination, source, _device);
        }
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
    
    /// <summary>
    /// Set up new thread for sniffing for replies and send the requests.
    /// </summary>
    public void ScanNetwork(IPAddress source, Dictionary<IPAddress, IpAddressInfo> destinations)
    {
        _device.Open(DeviceModes.Promiscuous);
        
        var thread = new Thread(() => PacketListener(destinations));
        thread.Start();
        
        Thread.Sleep(1000);

        // send packets
        SendPackets(destinations, source);
        
        Thread.Sleep(5000);

        _device.StopCapture();
        
        thread.Join(); 
        
        _device.Close();
    }
}