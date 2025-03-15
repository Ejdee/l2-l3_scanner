using System.Collections.Concurrent;
using System.Net;
using SharpPcap.LibPcap;

namespace ScannerLibrary.Interfaces;

public interface IProtocol
{
    void SendRequest(IPAddress source, IPAddress destination, LibPcapLiveDevice device);
    byte[] CreateHeader(IPAddress source, IPAddress destination, LibPcapLiveDevice device);
    void ProcessResponse(byte[] rawEthPacket, ConcurrentDictionary<IPAddress, ScanResult> dict);
}