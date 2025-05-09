using System.Net;
using ScannerLibrary.Utilities;

namespace ScannerLibrary.Tests;

public class IpUtilityTests
{
    [Fact]
    public void Ipv4MaskToBinaryTest()
    {
        // Arrange
        var ipUtility = new IpUtility();
        int mask = 24;
        string expected = "255.255.255.0";
        
        // Act
        string actual = ipUtility.MaskToIpv4Format(mask).ToString();
        

        // Assert
        Assert.Equal(expected, actual);
    }
    
    [Fact]
    public void InvalidIpv4MaskToBinaryTest()
    {
        // Arrange
        var ipUtility = new IpUtility();
        int mask = 33;
        
        // Act
        Action act = () => ipUtility.MaskToIpv4Format(mask);

        // Assert
        Assert.Throws<ArgumentOutOfRangeException>(act);
    }
    
    [Fact]
    public void Ipv6MaskToBinaryTest()
    {
        // Arrange
        var ipUtility = new IpUtility();
        int mask = 64;
        string expected = "ffff:ffff:ffff:ffff::";
        int mask2 = 35;
        string expected2 = "ffff:ffff:e000::";
        int mask3 = 126;
        string expected3 = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffc";
        
        // Act
        string actual = ipUtility.MaskToIpv6Format(mask).ToString();
        string actual2 = ipUtility.MaskToIpv6Format(mask2).ToString();
        string actual3 = ipUtility.MaskToIpv6Format(mask3).ToString();

        // Assert
        Assert.Equal(expected, actual);
        Assert.Equal(expected2, actual2);
        Assert.Equal(expected3, actual3);
    }
    
    [Fact]
    public void InvalidIpv6MaskToBinaryTest()
    {
        // Arrange
        var ipUtility = new IpUtility();
        int mask = 129;
        
        // Act
        Action act = () => ipUtility.MaskToIpv6Format(mask);

        // Assert
        Assert.Throws<ArgumentOutOfRangeException>(act);
    }

    [Fact]
    public void Ipv4SplitIpAddressTest()
    {
        // Arrange
        var ipUtility = new IpUtility();
        string address = "192.168.0.209/24";
        (string ip, int mask) expected = ("192.168.0.209", 24);

        // Act
        (string ip, int mask) actual = ipUtility.SplitIpAddress(address);

        // Assert
        Assert.Equal(expected, actual);
    }
    
    [Fact]
    public void Ipv6SplitIpAddressTest()
    {
        // Arrange
        var ipUtility = new IpUtility();
        string address = "2001:0db8:85a3:0000:0000:8a2e:0370:7334/64";
        (string ip, int mask) expected = ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", 64);

        // Act
        (string ip, int mask) actual = ipUtility.SplitIpAddress(address);

        // Assert
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void NextIpv4AddressTest()
    {
        // Arrange
        var ipUtility = new IpUtility();
        var ipBytes = new byte[] {192, 168, 0, 0};
        var expected = new byte[] {192, 168, 0, 1};
        var ipBytes2 = new byte[] {192, 168, 0, 255};
        var expected2 = new byte[] {192, 168, 1, 0};
        var ipBytes3 = new byte[] {192, 168, 255, 255};
        var expected3 = new byte[] {192, 169, 0, 0};
        
        
        // Act
        IPAddress actual = ipUtility.NextIpAddress(ipBytes);
        IPAddress actual2 = ipUtility.NextIpAddress(ipBytes2);
        IPAddress actual3 = ipUtility.NextIpAddress(ipBytes3);
        
        // Assert
        Assert.Equal(new IPAddress(expected), actual);
        Assert.Equal(new IPAddress(expected2), actual2);
        Assert.Equal(new IPAddress(expected3), actual3);
    }
    
    [Fact]
    public void NextIpv6AddressTest()
    {
        // Arrange
        var ipUtility = new IpUtility();
        var ipBytes = new byte[] {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34};
        var expected = new byte[] {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x35};
        var ipBytes2 = new byte[] {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0xff};
        var expected2 = new byte[] {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x74, 0x00};
        
        // Act
        IPAddress actual = ipUtility.NextIpAddress(ipBytes);
        IPAddress actual2 = ipUtility.NextIpAddress(ipBytes2);
        
        // Assert
        Assert.Equal(new IPAddress(expected), actual);
        Assert.Equal(new IPAddress(expected2), actual2);
    }

    [Fact]
    public void GetNumberOfHostsTest()
    {
        // Arrange
        var ipUtility = new IpUtility();
        string address = "192.168.0.0/25";
        int expected = 126;
        string address2 = "192.168.0.128/29";
        int expected2 = 6;
        string address3 = "fd00:cafe:0000:face::1/126";
        int expected3 = 3;
		string address4 = "fd00:cafe:0000:face::1/127";
		int expected4 = 2;
        
        
        // Act
        int actual = ipUtility.GetNumberOfHosts(address);
        int actual2 = ipUtility.GetNumberOfHosts(address2);
        int actual3 = ipUtility.GetNumberOfHosts(address3);
		int actual4 = ipUtility.GetNumberOfHosts(address4);
        
        // Assert
        Assert.Equal(expected, actual);
        Assert.Equal(expected2, actual2);
        Assert.Equal(expected3, actual3);
		Assert.Equal(expected4, actual4);
    }

    [Fact]
    public void GetIpv4AddressesTest()
    {
        // Arrange
        var ipUtility = new IpUtility();
        IEnumerable<string> subnet = new List<string>() { "192.168.0.0/30" , "192.168.0.128/29" };
        List<IPAddress> expected = new List<IPAddress>()
            { IPAddress.Parse("192.168.0.1"), IPAddress.Parse("192.168.0.2") ,
                IPAddress.Parse("192.168.0.129") , IPAddress.Parse("192.168.0.130") , IPAddress.Parse("192.168.0.131") , IPAddress.Parse("192.168.0.132") , IPAddress.Parse("192.168.0.133") , IPAddress.Parse("192.168.0.134")
                
            };
        
        // Act
        List<IPAddress> actual = ipUtility.GetIpAddresses(subnet);
        
        // Assert
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void GetIpv6AddressesTest()
    {
        // Arrange
        var ipUtility = new IpUtility();
        IEnumerable<string> subnet = new List<string>() { "fd00:cafe:0000:face::0/126" };
        List<IPAddress> expected = new List<IPAddress>()
            { IPAddress.Parse("fd00:cafe:0000:face::1") ,
                IPAddress.Parse("fd00:cafe:0000:face::2") , IPAddress.Parse("fd00:cafe:0000:face::3")
            };

		IEnumerable<string> subnet2 = new List<string>() { "fd00:cafe:0000:face::0/127" };
		List<IPAddress> expected2 = new List<IPAddress>()
			{
				IPAddress.Parse("fd00:cafe:0000:face::0"),
				IPAddress.Parse("fd00:cafe:0000:face::1")
			};
        
        // Act
        List<IPAddress> actual = ipUtility.GetIpAddresses(subnet);
		List<IPAddress> actual2 = ipUtility.GetIpAddresses(subnet2);
        
        // Assert
        Assert.Equal(expected, actual);
		Assert.Equal(expected2, actual2);
    }
    
    [Fact]
    public void GetSolictedNodeAddressTest()
    {
        // Arrange
        var ipUtility = new IpUtility();
        IPAddress address = IPAddress.Parse("2001:0db8:85a3:0000:0000:8a2e:0370:7334");
        IPAddress expected = IPAddress.Parse("ff02::1:ff70:7334");
        
        // Act
        IPAddress actual = ipUtility.GetSolicitedNodeAddress(address);
        
        // Assert
        Assert.Equal(expected, actual);
    }
}