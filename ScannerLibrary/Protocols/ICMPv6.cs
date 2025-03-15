using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using ScannerLibrary.Interfaces;
using SharpPcap.LibPcap;

namespace ScannerLibrary.Protocols;

public class IcmpV6 : IProtocol
{
   /// <summary>
   /// Send ICMPv6 ping request. Device parameter is not used but required by the interface.
   /// </summary>
   public void SendRequest(IPAddress source, IPAddress destination, LibPcapLiveDevice device)
   {
      using Socket socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.IcmpV6);
      socket.Bind(new IPEndPoint(source, 0));

      byte[] data = CreateHeader(source, destination, device);
      
      socket.SendTo(data, new IPEndPoint(destination, 0));
      Console.WriteLine("ICMPv6 packet sent from " + source + " to " + destination);
   }
   
   public void ProcessResponse(byte[] rawEthPacket, ConcurrentDictionary<IPAddress, ScanResult> dict)
   {
      byte[] ipAddr = new byte[16];
      
      Buffer.BlockCopy(rawEthPacket, 22, ipAddr, 0, 16);
      IPAddress ip = new IPAddress(ipAddr);
                        
      Console.WriteLine("Caught icmp reply from " + ip);
                        
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
      ushort checksum = CalculateIcmpChecksum(header, source, destination);
      header[2] = (byte)(checksum >> 8); // High byte
      header[3] = (byte)(checksum & 0xFF); // Low byte

      return header; 
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