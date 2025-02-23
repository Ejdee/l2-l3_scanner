using System.Net;
using System.Net.NetworkInformation;
using PacketDotNet;
using PacketDotNet.Utils;
using SharpPcap;
using SharpPcap.LibPcap;

namespace ScannerLibrary;

public class IcmpV4(LibPcapLiveDevice device)
{
    private const string GatewayAddress = "bc:0f:9a:5b:14:7c";

    /// <summary>
    /// Set up new thread for sniffing for ICMP replies and send the ICMP requests.
    /// </summary>
    public void IcmpProcess(IPAddress source, Dictionary<IPAddress, IpAddressInfo> destinations)
    {
        var thread = new Thread(() => ReceivingIcmpReply(destinations));
        thread.Start();
        
        Thread.Sleep(1000);

        foreach (var destination in destinations.Keys)
        {
            SendIcmpPacket(source, destination);
        }
        
        Thread.Sleep(5000);

        device.StopCapture();
        device.Close();
    }

    /// <summary>
    /// Unpack packet on arrival and check if it is ICMP reply.
    /// </summary>
    private void ReceivingIcmpReply(Dictionary<IPAddress, IpAddressInfo> dict)
    {
        device.OnPacketArrival += (sender, e) =>
        {
            var rawPacket = Packet.ParsePacket(e.GetPacket().LinkLayerType, e.GetPacket().Data);
            var ipPacket = rawPacket.Extract<IPPacket>();
            var icmpPacket = rawPacket.Extract<IcmpV4Packet>();

            if (icmpPacket != null && icmpPacket.TypeCode == IcmpV4TypeCode.EchoReply)
            {
                dict[ipPacket.SourceAddress].IcmpReply = true;
                Console.WriteLine("Received icmp packet from: " + ipPacket.SourceAddress);
            }
        };
        
        device.Open(DeviceModes.Promiscuous);
        Console.WriteLine();
        Console.WriteLine("-- Listening for replies...");
        
        device.StartCapture();
    }
    
    /// <summary>
    /// Construct icmp packet. Wrap it the IP packet and then ethernet frame before sending it.
    /// </summary>
    private void SendIcmpPacket(IPAddress source, IPAddress destination)
    {
        device.Open();

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