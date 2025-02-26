using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using PacketDotNet;
using PacketDotNet.Utils;
using SharpPcap;
using SharpPcap.LibPcap;
using ProtocolType = System.Net.Sockets.ProtocolType;

namespace ScannerLibrary;

public class IcmpV4()
{
    /// <summary>
    /// Construct icmp packet and send it.
    /// </summary>
    public void SendIcmpPacket(IPAddress source, IPAddress destination)
    {
        // create the IPv4 raw socket of protocol ICMP
        using Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp);
        socket.Bind(new IPEndPoint(source, 0));
        
        byte[] data = CreateIcmpHeader();

        socket.SendTo(data, new IPEndPoint(destination, 0));
            
        Console.WriteLine("ICMP packet sent from " + source + " to " + destination);
    }
    
    /// <summary>
    /// Manually create ICMP protocol header
    /// </summary>
    private byte[] CreateIcmpHeader()
    {
        // header for ICMP protocol is 8 bytes and 32 bytes payload
        byte[] header = new byte[8 + 32];

        header[0] = 8; // echo ping request
        header[1] = 0; // code
        header[2] = 0; // checksum
        header[3] = 0; // checksum
        header[4] = 0x12; // identifier (BE)
        header[5] = 0x34; // identifier (LE)
        header[6] = 0x00; // sequence number (BE)
        header[7] = 0x01; // sequence number (LE)
        
        byte[] payload = "IPK project ICMP."u8.ToArray();
        Array.Copy(payload, 0, header, 8, payload.Length);

        // Checksum by ChatGPT
        ushort checksum = CalculateIcmpChecksum(header);
        header[2] = (byte)(checksum >> 8); // High byte
        header[3] = (byte)(checksum & 0xFF); // Low byte

        return header;
    }

    /// <summary>
    /// 16-bit one's complement checksum by ChatGPT.
    /// </summary>
    private ushort CalculateIcmpChecksum(byte[] data)
    {
        uint sum = 0;

        // Sum all 16-bit words
        for (int i = 0; i < data.Length; i += 2)
        {
            ushort word = (ushort)((data[i] << 8) + (i + 1 < data.Length ? data[i + 1] : 0));
            sum += word;
        }

        // Add carry if any
        while ((sum >> 16) != 0)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // One's complement
        return (ushort)~sum;
    }
}