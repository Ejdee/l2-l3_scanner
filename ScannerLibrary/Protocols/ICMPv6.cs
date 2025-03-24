using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using ScannerLibrary.Interfaces;
using ScannerLibrary.Utilities;
using SharpPcap.LibPcap;

namespace ScannerLibrary.Protocols;

public class IcmpV6 : IProtocol
{
   private readonly ChecksumUtility _checksumUtility;

   public IcmpV6(ChecksumUtility checksumUtility)
   {
      _checksumUtility = checksumUtility;
   }

   /// <summary>
   /// Send ICMPv6 ping request. Device parameter is not used but required by the interface.
   /// </summary>
   public void SendRequest(IPAddress source, IPAddress destination, LibPcapLiveDevice device)
   {
      using Socket socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.IcmpV6);
      socket.Bind(new IPEndPoint(source, 0));

      byte[] data = CreateHeader(source, destination, device);
      
      socket.SendTo(data, new IPEndPoint(destination, 0));
      //Console.WriteLine("ICMPv6 packet sent from " + source + " to " + destination);
   }
   
   public void ProcessResponse(byte[] rawEthPacket, ConcurrentDictionary<IPAddress, ScanResult> dict)
   {
      byte[] ipAddr = new byte[16];
      
      Buffer.BlockCopy(rawEthPacket, 22, ipAddr, 0, 16);
      IPAddress ip = new IPAddress(ipAddr);
                        
      //Console.WriteLine("Caught icmp reply from " + ip);
                        
      if (dict.ContainsKey(ip))
      {
         dict[ip].IcmpReply = true;
      } 
   }

   /// <summary>
   /// Create ICMPv6 ping request header. Device parameter is not used but required by the interface.
   /// </summary>
   public byte[] CreateHeader(IPAddress source, IPAddress destination, LibPcapLiveDevice device)
   {
      // 8 bytes for ICMPv6 header and 56 bytes for payload
      byte[] header = new byte[8+56];
      
      header[0] = 0x80; // echo ping request
      header[1] = 0x00; // code
      header[2] = 0x00; // checksum
      header[3] = 0x00; // checksum
      header[4] = 0x12; // identifier (BE)
      header[5] = 0x34; // identifier (LE)
      header[6] = 0x00; // sequence number (BE)
      header[7] = 0x01; // sequence number (LE)

      byte[] payload = "IPK project ICMPv6."u8.ToArray();
      Array.Copy(payload, 0, header, 8, payload.Length);
      
      // Checksum by ChatGPT
      ushort checksum = _checksumUtility.CalculateIcmpv6Checksum(header, source, destination);
      header[2] = (byte)(checksum >> 8); // High byte
      header[3] = (byte)(checksum & 0xFF); // Low byte

      return header; 
   }
}