using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Text;

namespace ScannerLibrary;

public class IpHandler
{
    private const int Ipv4Length = 32; 
    private const int ReservedHostsCount = 2;
    private const int Ipv6Length = 128;
    
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