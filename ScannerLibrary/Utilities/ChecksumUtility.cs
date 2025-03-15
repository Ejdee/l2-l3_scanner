using System.Net;

namespace ScannerLibrary.Utilities;

public class ChecksumUtility
{
    /// <summary>
    /// 16-bit one's complement checksum.
    /// Made by ChatGPT.
    /// </summary>
    public ushort CalculateIcmpv4Checksum(byte[] data)
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
    
    /// <summary>
    /// Calculate ICMPv6 checksum (16-bit one's complement).
    /// Includes the pseudo-header.
    /// Made by ChatGPT.
    /// </summary>
    public ushort CalculateIcmpv6Checksum(byte[] data, IPAddress source, IPAddress destination)
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