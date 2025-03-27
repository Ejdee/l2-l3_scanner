using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using ScannerLibrary.Interfaces;
using ScannerLibrary.Protocols;
using SharpPcap;
using SharpPcap.LibPcap;

namespace ScannerLibrary.ScannerCore;

public class NetworkScanner
{
    private readonly IProtocol _icmp;
    private readonly IProtocol _icmp6;
    private readonly IProtocol _arp;
    private readonly IProtocol _ndp;
    private readonly LibPcapLiveDevice _device; 
    private const int OffsetIpv6 = 54;

    public NetworkScanner(LibPcapLiveDevice device)
    {
        _icmp = ProtocolFactory.GetProtocol(ProtocolTypes.Icmpv4);
        _arp = ProtocolFactory.GetProtocol(ProtocolTypes.Arp);
        _icmp6 = ProtocolFactory.GetProtocol(ProtocolTypes.Icmpv6);
        _ndp = ProtocolFactory.GetProtocol(ProtocolTypes.Ndp);
        _device = device;
    }
    
    /// <summary>
    /// Set up new thread for sniffing for replies and send the requests.
    /// </summary>
    public async Task ScanNetwork(IPAddress ipv4Source, IPAddress ipv6Source, ConcurrentDictionary<IPAddress, ScanResult> destinations, int timeout)
    {
        _device.Open(DeviceModes.Promiscuous);

        // Set filter to only capture ICMP, ICMPv6 (NDP), and ARP packets
        _device.Filter = "icmp or arp or (ip6 and ip6[6] == 58)";

        var listenerTask = Task.Run(() => PacketListener(destinations));

        SendArpRequests(destinations, ipv4Source, ipv6Source);
    
        Thread.Sleep(250);

        SendIcmpRequests(destinations, ipv4Source, ipv6Source);
    
        // Wait for responses
        await Task.Delay(timeout);

        await listenerTask;
        
        _device.StopCapture();
        _device.Close();
    }

    /// <summary>
    /// Get packet on arrival and check if it is some desired reply
    /// </summary>
    private void PacketListener(ConcurrentDictionary<IPAddress, ScanResult> dict)
    {
        _device.OnPacketArrival += (sender, e) =>
        {
            byte[] rawEthPacket = e.GetPacket().Data;

            byte[] ethType = new byte[] { rawEthPacket[12], rawEthPacket[13] };

            // ICMPv4
            if (ethType[0] == 0x08 && ethType[1] == 0x00)
            {
                _icmp.ProcessResponse(rawEthPacket, dict);
            }
            // IPv6
            else if (ethType[0] == 0x86 && ethType[1] == 0xdd)
            {
                // ICMPv6
                if (rawEthPacket[20] == 0x3a)
                {
                    // NDP - neighbor advertisement
                    if (rawEthPacket[OffsetIpv6] == 0x88)
                    {
                        _ndp.ProcessResponse(rawEthPacket, dict);
                    }

                    // ICMPv6 echo reply code
                    if (rawEthPacket[OffsetIpv6] == 0x81)
                    {
                        _icmp6.ProcessResponse(rawEthPacket, dict);
                    }
                }
            }
            // ARP
            else if (ethType[0] == 0x08 && ethType[1] == 0x06)
            {
                _arp.ProcessResponse(rawEthPacket, dict);
            }
        };

        _device.StartCapture();
    }
    
    private void SendIcmpRequests(ConcurrentDictionary<IPAddress, ScanResult> destinations, IPAddress ipv4Source, IPAddress ipv6Source)
    {
        foreach (var destination in destinations.Keys)
        {
            switch (destination.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    _icmp.SendRequest(ipv4Source, destination, _device);
                    break;
                case AddressFamily.InterNetworkV6:
                    _icmp6.SendRequest(ipv6Source, destination, _device);
                    break;
                default:
                    throw new NotImplementedException();
            }
        }
    }

    private void SendArpRequests(ConcurrentDictionary<IPAddress, ScanResult> destinations, IPAddress ipv4Source, IPAddress ipv6Source)
    {
        foreach (var destination in destinations.Keys)
        {
            switch (destination.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    _arp.SendRequest(ipv4Source, destination, _device);
                    break;
                case AddressFamily.InterNetworkV6:
                    _ndp.SendRequest(ipv6Source, destination, _device);
                    break;
            }
        }
    }
}