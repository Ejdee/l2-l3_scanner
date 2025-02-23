using System.Net;

namespace ScannerLibrary;

public class IpHandler
{
    private const int Ipv4Length = 32; 
    private const int ReservedHostsCount = 2;
    private const int Ipv6Length = 128;

    public List<IPAddress> IterateAndPrintHostIp(string ipAddress)
    {

        (string ip, int mask) = SplitIpAddress(ipAddress);
        
        IPAddress maskedIp = MaskToIpv4Format(mask);
        Console.WriteLine("prefix IP - " + maskedIp);
        
        byte[] ipBytes = IPAddress.Parse(ip).GetAddressBytes();
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

        return addresses;
    }

    private static IPAddress NextIpAddress(byte[] ipBytes)
    {
        // if there is overflow in the address, make the current byte zero and increment the byte to the left
        for (int i = ipBytes.Length-1; i >= 0; i--)
        {
            if (ipBytes[i] < 255)
            {
                ipBytes[i]++;
                return new IPAddress(ipBytes);
            }

            ipBytes[i] = 0;

            // overflow in the last byte
            if (i == 0)
            {
                throw new ArgumentException("Invalid IP address.");
            }
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
    public static int GetNumberOfHosts(string address)
    {
        
        // Split the IP address to IP and the mask
        (string ipString, int mask) = SplitIpAddress(address);

        if (IPAddress.TryParse(ipString, out var ipAddress))
        {
            // Calculate the number of available hosts based on the type of the IP address
            switch (ipAddress.AddressFamily)
            {
                case System.Net.Sockets.AddressFamily.InterNetwork:
                    return (int)(Math.Pow(2, Ipv4Length - mask)) - ReservedHostsCount;
                case System.Net.Sockets.AddressFamily.InterNetworkV6:
                    return (int)(Math.Pow(2, Ipv6Length - mask));
                default:
                    Console.WriteLine("Not a valid IP address");
                    throw new ArgumentOutOfRangeException();
            }
        }

        return -1;
    }

    /// <summary>
    /// Split the IP address to IP address and mask.
    /// </summary>
    private static (string, int)  SplitIpAddress(string address)
    {
        string[] splitAddress = address.Split('/');
        string ipString = splitAddress[0];
        string mask = splitAddress[1];

        return (ipString, int.Parse(mask));
    } 
    
}