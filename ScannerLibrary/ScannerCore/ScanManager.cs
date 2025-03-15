using ScannerLibrary.Utilities;

namespace ScannerLibrary.ScannerCore;

public class ScanManager
{
    private readonly DeviceManager _deviceManager = new();

    public async Task ScanAsync(string interfaceName, int timeout, IEnumerable<string> subnets)
    {
        var device = _deviceManager.GetDevice(interfaceName);
        if (device == null)
        {
            throw new Exception("No interface found with interface name " + interfaceName);
        }
        
        _deviceManager.PrintAvailableInterfaces();

        var sourceIps = _deviceManager.GetSourceAddresses(device);
        
        var ipHandler = new IpUtility();
        var addressResults = ipHandler.InitializeAddressesToScan(subnets);

        var scanner = new NetworkScanner(device);
        await scanner.ScanNetwork(sourceIps[0], sourceIps[1], addressResults, timeout);

        var logger = new Logger();
        logger.PrintResult(addressResults, subnets);
    }
}