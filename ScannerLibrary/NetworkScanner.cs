using System.Linq.Expressions;
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
    private const int OffsetIpv6 = 54;

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

        // set filter to only capture icmp, icmpv6 (ndp) and arp packets
        //_device.Filter = "icmp or arp or (ip6 and ip6[6] == 58)";
        
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
    /// Get packet on arrival and check if it is some desired reply
    /// </summary>
    private void PacketListener(Dictionary<IPAddress, IpAddressInfo> dict)
    {
        _device.OnPacketArrival += (sender, e) =>
        {
            byte[] rawEthPacket = e.GetPacket().Data;

            byte[] ethType = new byte[2] { rawEthPacket[12], rawEthPacket[13] };

            if (ethType[0] == 0x08 && ethType[1] == 0x00)
            {
                // IPV4 parsing - only ICMP in this case
                byte[] ipAddr = new byte[4];

                int headerSizeIpv4 = (rawEthPacket[14] & 0x0F) * 4;
                int offsetIpv4 = headerSizeIpv4 + 14;

                // ICMP protocol with type code 0 (reply)
                if (rawEthPacket[23] == 0x01 && rawEthPacket[offsetIpv4] == 0x00)
                {
                    // copy the IP address that packet was sent from
                    Buffer.BlockCopy(rawEthPacket, 26, ipAddr, 0, 4);
                    Console.WriteLine("Received ICMP from " + new IPAddress(ipAddr));
                }
            }
            else if (ethType[0] == 0x86 && ethType[1] == 0xdd)
            {
                // IPV6 PARSING
                // ICMPv6 as next header
                if (rawEthPacket[20] == 0x3a)
                {
                    byte[] ipAddr = new byte[16];
                    // If we caught neighbour advertisement type code, and it is non-solicited (contains MAC address)
                    if (rawEthPacket[OffsetIpv6] == 0x88 && rawEthPacket[OffsetIpv6 + 4] == 0x60)
                    {
                        Buffer.BlockCopy(rawEthPacket, OffsetIpv6 + 8, ipAddr, 0, 16);
                        Console.WriteLine("IP TARGET " + BitConverter.ToString(ipAddr));

                        byte[] macAddress = new byte[6];
                        Buffer.BlockCopy(rawEthPacket, OffsetIpv6 + 26, macAddress, 0, 6);
                        Console.WriteLine("MAC " + BitConverter.ToString(macAddress));
                    }

                    // ICMPv6 echo reply code
                    if (rawEthPacket[OffsetIpv6] == 0x81)
                    {
                        Buffer.BlockCopy(rawEthPacket, 22, ipAddr, 0, 16);
                        Console.WriteLine("ICMP - IP TARGET " + BitConverter.ToString(ipAddr));
                    }
                }
            }
            else if (ethType[0] == 0x08 && ethType[1] == 0x06)
            {
                // ARP parsing
                
                // if the opcode is reply
                if (rawEthPacket[20] == 0x00 && rawEthPacket[21] == 0x02)
                {
                    byte[] ipAddr = new byte[4];
                    byte[] macAddress = new byte[6];

                    Buffer.BlockCopy(rawEthPacket, 28, ipAddr, 0, 4);
                    Buffer.BlockCopy(rawEthPacket, 22, macAddress, 0, 6);

                    Console.WriteLine("ARP Reply from " + new IPAddress(ipAddr) + " MAC " +
                                      BitConverter.ToString(macAddress));
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