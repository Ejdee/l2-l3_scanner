using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Numerics;
using System.Text;

namespace ScannerLibrary;

public class IpHandler
{
    private const int Ipv4Length = 32; 
    private const int ReservedHostsCount = 2;
    private const int Ipv6Length = 128;

    private static void IterateAndPrintHostIp(IPAddress ipAddress, int mask)
    {
        IPAddress maskedIp = MaskToIpv4Format(mask);
        Console.WriteLine("prefix IP - " + maskedIp);
        
        byte[] ipBytes = ipAddress.GetAddressBytes();
        byte[] maskedIpBytes = maskedIp.GetAddressBytes();
        
        // IPv4 has 4 bytes, therefore create a new byte instance of size 4
        byte[] networkBytes = new byte[Ipv4Length/8];
        byte[] broadcastBytes = new byte[Ipv4Length/8];

        // get the network and broadcast address for passed IP range
        for (int i = 0; i < Ipv4Length / 8; i++)
        {
            networkBytes[i] = (byte)(ipBytes[i] & maskedIpBytes[i]);
            broadcastBytes[i] = (byte)(ipBytes[i] | ~maskedIpBytes[i]);
        }
        
        Console.WriteLine("Network: " + new IPAddress(networkBytes));
        Console.WriteLine("Broadcast: " + new IPAddress(broadcastBytes));
    }

    /// <summary>
    /// Convert the mask to appropriate IP address format using bit operations.
    /// </summary>
    private static IPAddress MaskToIpv4Format(int mask)
    {
        uint prefix = (uint)(~0 << (Ipv4Length - mask)); 
        return new IPAddress(BitConverter.GetBytes(prefix).Reverse().ToArray());
    }

    //private IPAddress MaskToIpv6Format(int mask)
    //{
    //}
    
    /// <summary>
    /// Calculate the number of available hosts from IP address.
    /// </summary>
    public int GetNumberOfHosts(string address)
    {
        
        // Split the IP address to IP and the mask
        string[] splittedAddress = address.Split('/');
        string ipString = splittedAddress[0];
        string mask = splittedAddress[1];

        if (IPAddress.TryParse(ipString, out var ipAddress))
        {
            // Calculate the number of available hosts based on the type of the IP address
            switch (ipAddress.AddressFamily)
            {
                case System.Net.Sockets.AddressFamily.InterNetwork:
                    IterateAndPrintHostIp(ipAddress, int.Parse(mask));
                    return (int)(Math.Pow(2, Ipv4Length - int.Parse(mask))) - ReservedHostsCount;
                case System.Net.Sockets.AddressFamily.InterNetworkV6:
                    return (int)(Math.Pow(2, Ipv6Length - int.Parse(mask)));
                default:
                    Console.WriteLine("Not a valid IP address");
                    throw new ArgumentOutOfRangeException();
            }
        }

        return -1;
    }
}