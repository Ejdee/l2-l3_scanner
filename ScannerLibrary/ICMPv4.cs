using System.Net;
using System.Net.NetworkInformation;
using PacketDotNet;
using PacketDotNet.Utils;
using SharpPcap;
using SharpPcap.LibPcap;

namespace ScannerLibrary;

public class IcmpV4()
{
    private const string GatewayAddress = "bc:0f:9a:5b:14:7c";

    /// <summary>
    /// Construct icmp packet. Wrap it the IP packet and then ethernet frame before sending it.
    /// </summary>
    public void SendIcmpPacket(IPAddress source, IPAddress destination, LibPcapLiveDevice device)
    {
        // ICMP header is 8 bytes + 32 bytes payload
        var icmpPacket = new IcmpV4Packet(new ByteArraySegment(new byte[8 + 32]));
        icmpPacket.TypeCode = IcmpV4TypeCode.EchoRequest;
        icmpPacket.Id = 0x1234;
        icmpPacket.Sequence = 1;
        icmpPacket.PayloadData = "Hello, are you there?"u8.ToArray();
        icmpPacket.Checksum = icmpPacket.CalculateIcmpChecksum();
        
        // Construct IP packet
        var ipPacket = new IPv4Packet(source, destination) { Protocol = PacketDotNet.ProtocolType.Icmp, PayloadPacket = icmpPacket };
        ipPacket.Checksum = ipPacket.CalculateIPChecksum();

        // Construct ethernet packet
        var ethernetPacket =
            new EthernetPacket(device.MacAddress, PhysicalAddress.Parse(GatewayAddress), EthernetType.IPv4)
            {
                PayloadPacket = ipPacket,
            };
        ethernetPacket.UpdateCalculatedValues();
        
        device.SendPacket(ethernetPacket);
        //Console.WriteLine("ICMP packet sent from " + source + " to " + destination);
    } 
}