using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using SharpPcap;
using SharpPcap.LibPcap;

namespace ScannerLibrary.ScannerCore;

public class DeviceManager
{
    private List<LibPcapLiveDevice> GetAvailableInterfaces() =>
        LibPcapLiveDeviceList.Instance.Where(d => d.Addresses.Count > 0).ToList();

    public LibPcapLiveDevice GetDevice(string interfaceName) =>
        GetAvailableInterfaces().FirstOrDefault(d => d.Name == interfaceName) ?? throw new InvalidOperationException("This interface doesn't exist");

    public List<IPAddress> GetSourceAddresses(LibPcapLiveDevice device,
        ConcurrentDictionary<IPAddress, ScanResult> addressResults)
    {
        // get the flags of the addresses that are going to be scanned
        bool isIpv4 = addressResults.Keys.Any(ip => ip.AddressFamily == AddressFamily.InterNetwork);
        bool isIpv6 = addressResults.Keys.Any(ip => ip.AddressFamily == AddressFamily.InterNetworkV6);
        
        List<IPAddress> sourcesIp = new List<IPAddress>();
        
        bool isIpv4Present = false;
        bool isIpv6Present = false;
        foreach (PcapAddress addr in device.Addresses)
        {
            var ip = addr.Addr?.ipAddress;

            if (ip != null)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    if (isIpv4Present)
                    {
                        continue;
                    }

                    sourcesIp.Add(ip);
                    isIpv4Present = true;
                }
                else if (ip.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    // include only link-local addresses
                    if (ip.ToString().StartsWith("fe80"))
                    {
                        if (isIpv6Present)
                        {
                            continue;
                        }

                        sourcesIp.Add(ip);
                        isIpv6Present = true;
                    }
                }
            }
        }

        // check if the network interface has the required IP addresses
        if (isIpv4 && isIpv6 && sourcesIp.Count < 2)
        {
            throw new InvalidOperationException("This network interface doesn't have both IPv4 and IPv6 addresses");
        } else if (isIpv4 && sourcesIp.All(i => i.AddressFamily != AddressFamily.InterNetwork))
        {
            throw new InvalidOperationException("This network interface doesn't have an IPv4 address");
        } else if (isIpv6 && sourcesIp.All(i => i.AddressFamily != AddressFamily.InterNetworkV6))
        {
            throw new InvalidOperationException("This network interface doesn't have an IPv6 address");
        }

        // Since the program expects IPv4 address to be the first one in the list and IPv6 the second one,
        // add random IPv4 address if the program won't scan IPv4 address or random IPv6 address if the program won't scan IPv6 address
        if (!isIpv4 && sourcesIp.All(i => i.AddressFamily != AddressFamily.InterNetwork))
        {
            sourcesIp.Insert(0, new IPAddress(0));
        } else if (!isIpv6 && sourcesIp.All(i => i.AddressFamily != AddressFamily.InterNetworkV6))
        {
            sourcesIp.Add(new IPAddress(0));
        }

        return sourcesIp;
    } 
    
    public void PrintAvailableInterfaces()
    {
        Console.WriteLine("Available Interfaces");
        var networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();

        foreach (var i in networkInterfaces)
        {
            // if the interface is not up, skip it
            if (i.OperationalStatus != OperationalStatus.Up) { continue; }
            
            var ipProperties = i.GetIPProperties();
            var ipAddresses = ipProperties.UnicastAddresses;
            
            Console.WriteLine("Name: " + i.Name);

            // if the interface has no IP addresses assigned, skip it
            if (ipAddresses.Count == 0) { continue; }
            
            foreach (var ip in ipAddresses)
            {
                if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    Console.WriteLine("\t IPv4: " + ip.Address);
                else if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                    Console.WriteLine("\t IPv6: " + ip.Address);
            }
        }
    }
}