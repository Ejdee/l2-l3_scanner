using System.Net;
using SharpPcap.LibPcap;

namespace ScannerLibrary.ScannerCore;

public class DeviceManager
{
    private List<LibPcapLiveDevice> GetAvailableInterfaces() =>
        LibPcapLiveDeviceList.Instance.Where(d => d.Addresses.Count > 0).ToList();

    public LibPcapLiveDevice GetDevice(string interfaceName) =>
        GetAvailableInterfaces().FirstOrDefault(d => d.Name == interfaceName) ?? throw new InvalidOperationException("This interface doesn't exist");

    public List<IPAddress> GetSourceAddresses(LibPcapLiveDevice device)
    {
        List<IPAddress> sourcesIp = new List<IPAddress>();
        
        foreach (PcapAddress addr in device.Addresses)
        {
            if (addr.Addr != null && 
                addr.Addr.ipAddress != null && 
                addr.Addr.ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                sourcesIp.Add(addr.Addr.ipAddress);
            } else if (addr.Addr is { ipAddress.AddressFamily: System.Net.Sockets.AddressFamily.InterNetworkV6 })
            {
                if(addr.Addr.ipAddress.ToString().StartsWith("fe80")) sourcesIp.Add(addr.Addr.ipAddress);
            }
        }

        return sourcesIp;
    } 
    
    public void PrintAvailableInterfaces()
    {
        Console.WriteLine("Available Interfaces");
        List<LibPcapLiveDevice> availableInterfaces = GetAvailableInterfaces();
        foreach (LibPcapLiveDevice liveDevice in availableInterfaces)
        {
            if (liveDevice.Addresses.Count <= 0)
            {
                continue;
            }

            Console.WriteLine("\t Name: " + liveDevice.Name);

            foreach (PcapAddress addr in liveDevice.Addresses)
            {
                if (addr.Addr != null &&
                    addr.Addr.ipAddress != null &&
                    addr.Addr.ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    Console.WriteLine("\t \t IPv4 : " + addr.Addr.ipAddress);
                }
                else if (addr.Addr is { ipAddress.AddressFamily: System.Net.Sockets.AddressFamily.InterNetworkV6 })
                {
                    Console.WriteLine("\t \t IPv6 : " + addr.Addr.ipAddress);
                }
            }

            break;
        }
    }
}