using System.Net;
using System.Net.Sockets;
using SharpPcap.LibPcap;

namespace ScannerLibrary;

public class Ndp
{
    public void SendNdpRequest(IPAddress source, IPAddress destination, LibPcapLiveDevice device)
    {
        using Socket socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.IcmpV6);
        
        socket.Bind(new IPEndPoint(source, 0));
        
        byte[] nsHeader = CreateNsHeader(source, destination, device);

        IPAddress solicitedNodeAddress = GetSolicitedNodeAddress(destination);
        
        socket.SendTo(nsHeader, new IPEndPoint(solicitedNodeAddress, 0));
        Console.WriteLine("Sent NDP request to " + solicitedNodeAddress + " from " + source);
    }

    private IPAddress GetSolicitedNodeAddress(IPAddress destination)
    {
        byte[] addressBytes = destination.GetAddressBytes();
        byte[] solicitedNodeAddress = new byte[16]
        {
            0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF,
            addressBytes[13], addressBytes[14], addressBytes[15]
        };

        return new IPAddress(solicitedNodeAddress);
    }

    private byte[] CreateNsHeader(IPAddress source, IPAddress destination, LibPcapLiveDevice device)
    {
        byte[] nsHeader = new byte[32];

        nsHeader[0] = 0x87; // type
        nsHeader[1] = 0x00; // code
        nsHeader[2] = 0x00; // checksum
        nsHeader[3] = 0x00;
        nsHeader[4] = 0x00; // reserved
        nsHeader[5] = 0x00;
        nsHeader[6] = 0x00;
        nsHeader[7] = 0x00;
        
        byte[] targetAddress = destination.GetAddressBytes(); 
        Array.Copy(targetAddress, 0, nsHeader, 8, targetAddress.Length);

        nsHeader[24] = 0x01;
        nsHeader[25] = 0x01;
        
        // 6 bytes of source mac address
        byte[] sourceMac = device.MacAddress.GetAddressBytes();
        Array.Copy(sourceMac, 0, nsHeader, 26, sourceMac.Length);

        // Checksum by ChatGPT
        ushort checksum = CalculateIcmpChecksum(nsHeader, source, GetSolicitedNodeAddress(destination));
        nsHeader[2] = (byte)(checksum >> 8); // High byte
        nsHeader[3] = (byte)(checksum & 0xFF); // Low byte 

        return nsHeader;
    }
    
    /// <summary>
    /// Calculate ICMPv6 checksum (16-bit one's complement).
    /// Includes the pseudo-header.
    /// </summary>
    private ushort CalculateIcmpChecksum(byte[] data, IPAddress source, IPAddress destination)
    {
        uint sum = 0;

        // Pseudo-header: Source address (16 bytes), Destination address (16 bytes), Zero, Next Header (1 byte), Length (2 bytes)
        byte[] pseudoHeader = new byte[40];
        
        // Copy source address
        Array.Copy(source.GetAddressBytes(), 0, pseudoHeader, 0, 16);
        // Copy destination address
        Array.Copy(destination.GetAddressBytes(), 0, pseudoHeader, 16, 16);
        // Next header (ICMPv6)
        pseudoHeader[32] = 0x00; // Reserved byte (set to zero)
        pseudoHeader[33] = 0x3A; // Protocol (ICMPv6 = 58)
        // Length of ICMPv6 data (Header + Payload)
        pseudoHeader[34] = (byte)((data.Length) >> 8);
        pseudoHeader[35] = (byte)(data.Length & 0xFF);

        // Add pseudo-header to checksum calculation
        sum = AddToChecksum(sum, pseudoHeader);

        // Add ICMPv6 data to checksum calculation
        sum = AddToChecksum(sum, data);

        // Add carry if any
        while ((sum >> 16) != 0)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // One's complement
        return (ushort)~sum;
    }

    private uint AddToChecksum(uint sum, byte[] data)
    {
        for (int i = 0; i < data.Length; i += 2)
        {
            ushort word = (ushort)((data[i] << 8) + (i + 1 < data.Length ? data[i + 1] : 0));
            sum += word;
        }

        return sum;
    }
}