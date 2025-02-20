using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
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
        
        // Increment network address until it is not equal to broadcast. Store each address
        List<IPAddress> addresses = [];
        while (!Equals(new IPAddress(broadcastBytes), NextIpAddress(networkBytes)))
        {
            addresses.Add(new IPAddress(networkBytes));
        }

        Console.WriteLine(addresses.Count);
        foreach (var add in addresses)
        {
            Console.WriteLine(add.ToString());
        }
    }

    private static IPAddress NextIpAddress(byte[] ipBytes)
    {
        int byteModify = (Ipv4Length / 8) - 1;
        while (byteModify >= 0)
        {
            if (ipBytes[byteModify] < 255)
            {
                ipBytes[byteModify]++;
                return new IPAddress(ipBytes);
            }

            // if there is overflow in the address, make the current byte zero and increment the byte to the left
            for (int i = byteModify; i >= 0; i--)
            {
                if (ipBytes[i] < 255)
                {
                    ipBytes[i]++;
                    break;
                }
            }
            ipBytes[byteModify] = 0;
        }
        return new IPAddress(ipBytes);
    }

    /// <summary>
    /// Convert the mask to appropriate IP address format using bit operations.
    /// </summary>
    private static IPAddress MaskToIpv4Format(int mask)
    {
        uint prefix = (uint)(~0 << (Ipv4Length - mask)); 
        return new IPAddress(BitConverter.GetBytes(prefix).Reverse().ToArray());
    }
    
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