using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using ProtocolType = System.Net.Sockets.ProtocolType;

namespace ScannerLibrary;

public class Arp
{
    /// <summary>
    /// Create arp header and send it.
    /// </summary>
    public void SendArpRequest(IPAddress destination, IPAddress source, LibPcapLiveDevice device)
    {
        byte[] arpHeader = CreateArpHeader(source, destination, device);

        //TODO: search internet for possibility of sending raw ethernet frames in c#
        device.SendPacket(arpHeader);
    }

    private static byte[] CreateArpHeader(IPAddress source, IPAddress destination, LibPcapLiveDevice device)
    {
        byte[] ethHeader = new byte[14];

        // 6 bytes of ethernet address of destination
        byte[] broadcast = new byte[] {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        Array.Copy(broadcast, 0, ethHeader, 0, broadcast.Length);

        // 6 bytes of source mac address
        byte[] sourceMac = device.MacAddress.GetAddressBytes();
        Array.Copy(sourceMac, 0, ethHeader, 6, sourceMac.Length);

        // type: ARP
        ethHeader[12] = 0x08;
        ethHeader[13] = 0x06;

        byte[] arpHeader = new byte[28];

        arpHeader[0] = 0x00; // hardware type
        arpHeader[1] = 0x01;
        arpHeader[2] = 0x08; // protocol type
        arpHeader[3] = 0x00;
        arpHeader[4] = 0x06; // hardware size
        arpHeader[5] = 0x04; // protocol size
        arpHeader[6] = 0x00; // opcode
        arpHeader[7] = 0x01; 
        
        // sender MAC address
        Array.Copy(sourceMac, 0, arpHeader, 8, sourceMac.Length);
        
        // sender IP address
        Array.Copy(source.GetAddressBytes(), 0, arpHeader, 14, source.GetAddressBytes().Length);

        // target MAC address (doesn't matter, we set it to all F's)
        Array.Copy(broadcast, 0, arpHeader, 18, broadcast.Length);
        
        // target IP address
        Array.Copy(destination.GetAddressBytes(), 0, arpHeader, 24, destination.GetAddressBytes().Length);
        
        byte[] arpPacket = new byte[ethHeader.Length + arpHeader.Length];
        Array.Copy(ethHeader, 0, arpPacket, 0, ethHeader.Length);
        Array.Copy(arpHeader, 0, arpPacket, ethHeader.Length, arpHeader.Length);
        
        return arpPacket;
    }
}