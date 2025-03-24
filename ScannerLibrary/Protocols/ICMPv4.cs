using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using ScannerLibrary.Interfaces;
using ScannerLibrary.Utilities;
using SharpPcap.LibPcap;

namespace ScannerLibrary.Protocols;

public class IcmpV4 : IProtocol
{
    private readonly ChecksumUtility _checksumUtility;

    public IcmpV4(ChecksumUtility checksumUtility)
    {
        _checksumUtility = checksumUtility;
    }

    /// <summary>
    /// Construct icmp packet and send it.
    /// </summary>
    public void SendRequest(IPAddress source, IPAddress destination, LibPcapLiveDevice device)
    {
        // create the IPv4 raw socket of protocol ICMP
        using Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp);
        socket.Bind(new IPEndPoint(source, 0));
        
        byte[] data = CreateHeader(source, destination, device);

        socket.SendTo(data, new IPEndPoint(destination, 0));
        //Console.WriteLine("ICMP request sent to " + destination + " from " + source);
    }
    
    public void ProcessResponse(byte[] rawEthPacket, ConcurrentDictionary<IPAddress, ScanResult> dict)
    {
        byte[] ipAddr = new byte[4];

        int headerSizeIpv4 = (rawEthPacket[14] & 0x0F) * 4;
        int offsetIpv4 = headerSizeIpv4 + 14;

        // ICMP protocol with type code 0 (reply)
        if (rawEthPacket[23] == 0x01 && rawEthPacket[offsetIpv4] == 0x00)
        {
            // copy the IP address that packet was sent from
            Buffer.BlockCopy(rawEthPacket, 26, ipAddr, 0, 4);
            IPAddress ip = new IPAddress(ipAddr);

            //Console.WriteLine("Caught icmp from " + ip); 
                    
            if (dict.ContainsKey(ip))
            {
                dict[ip].IcmpReply = true;
            }
        }
    }
    
    /// <summary>
    /// Manually create ICMP protocol header. Parameters of the function are not used but required by the interface.
    /// </summary>
    public byte[] CreateHeader(IPAddress source, IPAddress destination, LibPcapLiveDevice device)
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
        
        byte[] payload = "IPK project ICMPv4."u8.ToArray();
        Array.Copy(payload, 0, header, 8, payload.Length);

        // Checksum by ChatGPT
        ushort checksum = _checksumUtility.CalculateIcmpv4Checksum(header);
        header[2] = (byte)(checksum >> 8); // High byte
        header[3] = (byte)(checksum & 0xFF); // Low byte

        return header;
    }
}