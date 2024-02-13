package scan

import (
	"github.com/google/gopacket/pcap"
	"github.com/libp2p/go-netroute"
	"github.com/projectdiscovery/gologger"
)

type NetWorkInfo struct {
	DeviceName string
	SrcIP      string
	SrcMac     string
	GatewayIP  string
}

// GetBaseInfo 获取设备的基础信息 SrcIP SrcMac GatewayIP DeviceName
func (n *NetWorkInfo) GetBaseInfo(desIP string) *NetWorkInfo {
	router, err := netroute.New()
	if err != nil {
		gologger.Error().Msg(err.Error())
		return n
	}
	iface, gateway, preferredSrc, err := router.Route(ipStrToIPv4(desIP))
	if err != nil {
		gologger.Error().Msg(err.Error())
		return n
	}
	n.SrcMac = iface.HardwareAddr.String()
	n.SrcIP = preferredSrc.String()
	if gateway != nil {
		n.GatewayIP = gateway.String()
	}
	devices, err := pcap.FindAllDevs()
	if err != nil {
		gologger.Error().Msg(err.Error())
		return n
	}
	for _, device := range devices {
		if len(device.Addresses) > 0 && device.Addresses[0].IP.String() == preferredSrc.String() {
			n.DeviceName = device.Name
			break
		}
	}
	return n
}
