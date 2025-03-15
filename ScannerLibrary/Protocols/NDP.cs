using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using ScannerLibrary.Interfaces;
using ScannerLibrary.Utilities;
using SharpPcap.LibPcap;

namespace ScannerLibrary.Protocols;

public class Ndp : IProtocol
{
    private readonly IpUtility _ipUtility;
    private readonly ChecksumUtility _checksumUtility;

    public Ndp(IpUtility ipUtility, ChecksumUtility checksumUtility)
    {
        _ipUtility = ipUtility;
        _checksumUtility = checksumUtility;
    }

    public void SendRequest(IPAddress source, IPAddress destination, LibPcapLiveDevice device)
    {
        using Socket socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.IcmpV6);
        
        socket.Bind(new IPEndPoint(source, 0));
        
        byte[] nsHeader = CreateHeader(source, destination, device);

        IPAddress solicitedNodeAddress = _ipUtility.GetSolicitedNodeAddress(destination);
        
        socket.SendTo(nsHeader, new IPEndPoint(solicitedNodeAddress, 0));
        Console.WriteLine("Sent NDP request to " + solicitedNodeAddress + " from " + source);
    }

    public void ProcessResponse(byte[] rawEthPacket, ConcurrentDictionary<IPAddress, ScanResult> dict)
    {
        const int offsetIpv6 = 54;
        byte[] ipAddr = new byte[16]; 
        
        Buffer.BlockCopy(rawEthPacket, offsetIpv6 + 8, ipAddr, 0, 16);
        IPAddress ip = new IPAddress(ipAddr);

        byte[] macAddress = new byte[6];
        Buffer.BlockCopy(rawEthPacket, offsetIpv6 + 26, macAddress, 0, 6);

        Console.WriteLine("Caught ndp from " + ip + " with mac " + BitConverter.ToString(macAddress)); 
                        
        if (dict.ContainsKey(ip))
        {
            dict[ip].ArpSuccess = true;
            dict[ip].MacAddress = BitConverter.ToString(macAddress);
        }
    }

    public byte[] CreateHeader(IPAddress source, IPAddress destination, LibPcapLiveDevice device)
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
        ushort checksum = _checksumUtility.CalculateIcmpv6Checksum(nsHeader, source, _ipUtility.GetSolicitedNodeAddress(destination));
        nsHeader[2] = (byte)(checksum >> 8); // High byte
        nsHeader[3] = (byte)(checksum & 0xFF); // Low byte 

        return nsHeader;
    }
}