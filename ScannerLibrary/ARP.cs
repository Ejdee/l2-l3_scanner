using System.Net;
using System.Net.NetworkInformation;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace ScannerLibrary;

public class Arp
{
    public void SendArpRequest(IPAddress destination, IPAddress source, LibPcapLiveDevice device)
    {
        var arpSocket = new ArpPacket(ArpOperation.Request, device.MacAddress, destination,
            device.Addresses[0].Addr.hardwareAddress, source);
        
        var ethernetPacket = new EthernetPacket(device.Addresses[0].Addr.hardwareAddress, PhysicalAddress.Parse("FF:FF:FF:FF:FF:FF"), EthernetType.Arp);
        ethernetPacket.PayloadPacket = arpSocket;
        ethernetPacket.UpdateCalculatedValues();
        
        device.SendPacket(ethernetPacket);
        //Console.WriteLine("arp packet sent from " + source + " to " + destination);
    } 
}