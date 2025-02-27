using System.Net;
using System.Net.Sockets;
using System.Reflection.Metadata;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace ScannerLibrary;

public class NetworkScanner
{
    private readonly IcmpV4 _icmp;
    private readonly IcmpV6 _icmp6;
    private readonly Arp _arp;
    private readonly LibPcapLiveDevice _device;

    public NetworkScanner(IcmpV4 icmp, Arp arp, LibPcapLiveDevice device, IcmpV6 icmp6)
    {
        _icmp = icmp;
        _arp = arp;
        _device = device;
        _icmp6 = icmp6;
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
            
            // handle packet for ICMPv4
            var ipPacket = rawPacket.Extract<IPPacket>();
            var icmpPacket = rawPacket.Extract<IcmpV4Packet>();
            
            if (icmpPacket != null && icmpPacket.TypeCode == IcmpV4TypeCode.EchoReply)
            {
                if (dict.ContainsKey(ipPacket.SourceAddress))
                {
                    dict[ipPacket.SourceAddress].IcmpReply = true;
                    Console.WriteLine("Received icmp packet from: " + ipPacket.SourceAddress);
                }
            }
            
            // handle packet for ICMPv6
            var ipv6Packet = rawPacket.Extract<IPv6Packet>();
            var icmpv6Packet = rawPacket.Extract<IcmpV6Packet>();

            if (ipv6Packet != null && icmpv6Packet != null && icmpv6Packet.Type == IcmpV6Type.EchoReply)
            {

                if (dict.ContainsKey(ipv6Packet.SourceAddress))
                {
                    dict[ipv6Packet.SourceAddress].IcmpReply = true;
                    Console.WriteLine("Received icmp packet from: " + ipv6Packet.SourceAddress);
                }
                else
                {
                    Console.WriteLine("Received icmp reply from unknown address.");
                }
            }
            
            // handle packet for ARP
            var arpPacket = rawPacket.Extract<ArpPacket>();
            if (arpPacket != null && arpPacket.Operation == ArpOperation.Response)
            {
                var senderIp = arpPacket.SenderProtocolAddress;
                if (dict.ContainsKey(senderIp))
                {
                    dict[senderIp].ArpSuccess = true;
                    dict[senderIp].MacAddress = arpPacket.SenderHardwareAddress.ToString();
                    Console.WriteLine("Received arp packet from: " + senderIp);
                }
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
            switch (destination.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    _arp.SendArpRequest(destination, source, _device);
                    break;
                case AddressFamily.InterNetworkV6:
                    break;
                default:
                    throw new NotImplementedException();
            }
        }
    }

    private void SendIcmpRequests(Dictionary<IPAddress, IpAddressInfo> destinations, IPAddress source)
    {
        foreach (var destination in destinations)
        {
            switch (destination.Key.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    _icmp.SendIcmpv4Packet(source, destination.Key);
                    break;
                case AddressFamily.InterNetworkV6:
                    //_icmp6.SendIcmpv6Packet(source, destination.Key);
                    break;
            }
        }
    }
}