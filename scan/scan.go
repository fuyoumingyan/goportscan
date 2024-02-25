package scan

import (
	"context"
	"fmt"
	"github.com/dchest/siphash"
	"github.com/fuyoumingyan/utils/progress"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/phayes/freeport"
	_ "github.com/projectdiscovery/fdmax/autofdmax"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ratelimit"
	"github.com/schollz/progressbar/v3"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"
)

type Scan struct {
	IPS              []string
	NetWorkBaseInfo  *NetWorkInfo                   // 基础的网络信息 几乎所有构造请求的都是需要使用这个信息的
	Handle           *pcap.Handle                   // 一个 Handle , 再初始状态就需要去一直监听
	MacAddressMap    sync.Map                       // 存储 mac 地址的一个 map
	ResultMap        map[string]map[uint16]struct{} // 存储 IP 和开放端口的管道
	FirewallsMap     map[string]struct{}            // 存储可能防火墙的 IP
	SeqMap           sync.Map                       // 存储 SEQ 序列号的 MAP , 在监听操作的时候通过 key + 1 来判断是否是目标
	SerializeOptions gopacket.SerializeOptions      // 发包序列化设置
	bufferPool       sync.Pool                      // 缓存区池子
	wg               sync.WaitGroup                 // 监听协程和控制结束协程的控制操作
	limiter          *ratelimit.Limiter
	ctx              context.Context
	r                *rand.Rand
	cancel           context.CancelFunc
	entropy          uint64 // 密钥
	allPorts         []uint16
	bar              *progressbar.ProgressBar // 进度条
	allWait          int
}

// NewScan 端口扫描
// show : 进度条走完之后是否显示
// rate => 速率 3000
// allWaite => SYN包发完后等待多少秒 10
func NewScan(ips []string, rate int, allWait int, show bool) *Scan {
	if len(ips) <= 0 {
		gologger.Fatal().Msg("targets is null !")
		return nil
	}
	s := new(Scan)
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.allWait = allWait
	for _, ip := range ips {
		if ipStrToIPv4(ip) == nil {
			gologger.Fatal().Msgf("%v is not a valid IPv4 address !\n", ip)
		}
	}
	s.limiter = ratelimit.New(context.Background(), uint(rate), time.Second)
	s.FirewallsMap = make(map[string]struct{}, len(ips))
	s.bar = progress.NewProgressbar(int64(65535*len(ips)), "端口扫描", show)
	s.IPS = ips
	s.r = rand.New(rand.NewSource(time.Now().UnixNano()))
	s.allPorts = generatePortSlices(s.r)
	s.ResultMap = make(map[string]map[uint16]struct{})
	s.NetWorkBaseInfo = new(NetWorkInfo).GetBaseInfo(ips[0])
	s.SerializeOptions = gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	s.bufferPool = sync.Pool{
		New: func() interface{} {
			return gopacket.NewSerializeBuffer()
		},
	}
	s.entropy = s.r.Uint64()
	handle, err := pcap.OpenLive(s.NetWorkBaseInfo.DeviceName, 1024, false, pcap.BlockForever)
	if err != nil {
		return nil
	}
	expr := fmt.Sprintf("arp || tcp[13] == 0x12")
	err = handle.SetBPFFilter(expr)
	if err != nil {
		gologger.Error().Msgf("handle.SetBPFFilter(expr) error : %v", err.Error())
		return nil
	}
	s.Handle = handle
	s.wg.Add(1)
	go s.Listen()
	return s
}

func (s *Scan) sendACK(desMac, desIP string, desPort uint16) {
	eth := layers.Ethernet{
		SrcMAC:       macStrToMac(s.NetWorkBaseInfo.SrcMac),
		DstMAC:       macStrToMac(desMac),
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := layers.IPv4{
		SrcIP:    ipStrToIPv4(s.NetWorkBaseInfo.SrcIP),
		DstIP:    ipStrToIPv4(desIP),
		Version:  4,
		TTL:      128,
		Id:       uint16(40000 + s.r.Intn(10000)),
		Flags:    layers.IPv4DontFragment,
		Protocol: layers.IPProtocolTCP,
	}
	srcPort, err := freeport.GetFreePort()
	seq := s.synCookie(desIP, desPort, uint16(srcPort))
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(desPort),
		SYN:     true,
		Window:  65280,
		Seq:     seq,
		Options: []layers.TCPOption{
			{
				OptionType:   layers.TCPOptionKindMSS,
				OptionLength: 4,
				OptionData:   []byte{0x05, 0x50},
			},
			{
				OptionType: layers.TCPOptionKindNop,
			},
			{
				OptionType:   layers.TCPOptionKindWindowScale,
				OptionLength: 3,
				OptionData:   []byte{0x08},
			},
			{
				OptionType: layers.TCPOptionKindNop,
			},
			{
				OptionType: layers.TCPOptionKindNop,
			},
			{
				OptionType:   layers.TCPOptionKindSACKPermitted,
				OptionLength: 2,
			},
		},
	}
	err = tcp.SetNetworkLayerForChecksum(&ip4)
	if err != nil {
		return
	}
	buffer := s.bufferPool.Get().(gopacket.SerializeBuffer)
	defer func() {
		err := buffer.Clear()
		if err != nil {
			gologger.Error().Msgf("buf.Clear() error : %v", err)
		}
		s.bufferPool.Put(buffer)
	}()
	err = gopacket.SerializeLayers(buffer, s.SerializeOptions, &eth, &ip4, &tcp)
	if err != nil {
		gologger.Error().Msgf("gopacket.SerializeLayers error : %v", err.Error())
	}
	err = s.Handle.WritePacketData(buffer.Bytes())
	if err != nil {
		gologger.Error().Msgf("Handle.WritePacketData(buffer.Bytes()[:42]) error : %v", err)
	}
	s.SeqMap.Store(seq, desIP)
}

func (s *Scan) synCookie(desIP string, desPort uint16, srcPort uint16) uint32 {
	ipThem := net.ParseIP(desIP).To4()
	ipMe := net.ParseIP(s.NetWorkBaseInfo.SrcIP).To4()
	data := make([]byte, 0, 16)
	data = append(data, ipThem...)
	data = append(data, byte(desPort>>8), byte(desPort&0xff))
	data = append(data, ipMe...)
	data = append(data, byte(srcPort>>8), byte(srcPort&0xff))
	hash := siphash.Hash(s.entropy, s.entropy, data)
	return uint32(hash)
}

func (s *Scan) sendArpToGetMac(desIP string) {
	srcMac, mac := net.ParseMAC(s.NetWorkBaseInfo.SrcMac)
	if mac != nil {
		return
	}
	eth := layers.Ethernet{
		SrcMAC:       srcMac,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(srcMac),
		SourceProtAddress: []byte(ipStrToIPv4(s.NetWorkBaseInfo.SrcIP)),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(ipStrToIPv4(desIP)),
	}
	buffer := s.bufferPool.Get().(gopacket.SerializeBuffer)
	defer func() {
		err := buffer.Clear()
		if err != nil {
			gologger.Error().Msgf("buf.Clear() error : %v", err)
		}
		s.bufferPool.Put(buffer)
	}()
	err := gopacket.SerializeLayers(buffer, s.SerializeOptions, &eth, &arp)
	if err != nil {
		gologger.Error().Msgf("gopacket.SerializeLayers error : %v", err.Error())
	}
	err = s.Handle.WritePacketData(buffer.Bytes())
	if err != nil {
		gologger.Error().Msgf("Handle.WritePacketData(buffer.Bytes()[:42]) error : %v", err)
	}
}

func (s *Scan) getDesIPMacAddress(desIP string) string {
	if !net.ParseIP(desIP).IsPrivate() {
		if s.NetWorkBaseInfo.GatewayIP == "" {
			s.NetWorkBaseInfo = new(NetWorkInfo).GetBaseInfo(desIP)
		}
		if s.NetWorkBaseInfo.GatewayIP != "" {
			desIP = s.NetWorkBaseInfo.GatewayIP
		}
	}
	if value, ok := s.MacAddressMap.Load(desIP); ok {
		return value.(string)
	}
	s.sendArpToGetMac(desIP)
	for {
		if value, ok := s.MacAddressMap.Load(desIP); ok {
			return value.(string)
		}
	}
}

func generatePortSlices(r *rand.Rand) []uint16 {
	const maxPortNumber = 65535
	topPortsMap := make(map[uint16]struct{})
	var nonTopPorts []uint16
	for _, port := range TopTcpPorts {
		topPortsMap[port] = struct{}{}
	}
	for port := uint16(1); true; port++ {
		if _, exists := topPortsMap[port]; !exists {
			nonTopPorts = append(nonTopPorts, port)
		}
		if port == maxPortNumber {
			break
		}
	}
	for i := len(nonTopPorts) - 1; i > 0; i-- {
		j := r.Intn(i + 1)
		nonTopPorts[i], nonTopPorts[j] = nonTopPorts[j], nonTopPorts[i]
	}
	TopTcpPorts = append(TopTcpPorts, nonTopPorts...)
	return TopTcpPorts
}

func (s *Scan) run(desIP string) {
	DesMac := s.getDesIPMacAddress(desIP)
	for _, port := range s.allPorts {
		if len(s.ResultMap[desIP]) > 500 {
			s.FirewallsMap[desIP] = struct{}{}
			return
		}
		s.limiter.Take()
		s.sendACK(DesMac, desIP, port)
		err := s.bar.Add(1)
		if err != nil {
			gologger.Info().Msg(err.Error())
			return
		}
	}
}

func (s *Scan) RunEnumeration() *Scan {
	for _, ip := range s.IPS {
		s.run(ip)
	}
	s.Cancel()
	err := s.bar.Finish()
	if err != nil {
		gologger.Error().Msg(err.Error())
		return s
	}
	return s
}

func (s *Scan) sendRST(dstIP string, tcpPacket *layers.TCP) {
	eth := layers.Ethernet{
		SrcMAC:       macStrToMac(s.NetWorkBaseInfo.SrcMac),
		DstMAC:       macStrToMac(s.getDesIPMacAddress(dstIP)),
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := layers.IPv4{
		SrcIP:    []byte(ipStrToIPv4(s.NetWorkBaseInfo.SrcIP)),
		DstIP:    []byte(ipStrToIPv4(dstIP)),
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		SrcPort: tcpPacket.DstPort,
		DstPort: tcpPacket.SrcPort,
		RST:     true,
		ACK:     true,
		Ack:     tcpPacket.Seq + 1,
		Seq:     tcpPacket.Ack,
	}
	err := tcp.SetNetworkLayerForChecksum(&ip4)
	if err != nil {
		return
	}
	buffer := s.bufferPool.Get().(gopacket.SerializeBuffer)
	defer func() {
		err := buffer.Clear()
		if err != nil {
			gologger.Error().Msgf("buf.Clear() error : %v", err)
		}
		s.bufferPool.Put(buffer)
	}()
	err = gopacket.SerializeLayers(buffer, s.SerializeOptions, &eth, &ip4, &tcp)
	if err != nil {
		gologger.Error().Msgf("gopacket.SerializeLayers error : %v", err.Error())
	}
	err = s.Handle.WritePacketData(buffer.Bytes())
	if err != nil {
		gologger.Error().Msgf("Handle.WritePacketData(buffer.Bytes()[:42]) error : %v", err)
	}
}

func (s *Scan) Listen() {
	packetSource := gopacket.NewPacketSource(s.Handle, s.Handle.LinkType())
	defer s.wg.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		case packet, ok := <-packetSource.Packets():
			if !ok {
				return
			}
			if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
				arpPacket, _ := arpLayer.(*layers.ARP)
				ipStr := net.IP(arpPacket.SourceProtAddress).String()
				if _, ok := s.MacAddressMap.Load(ipStr); !ok {
					s.MacAddressMap.Store(ipStr, net.HardwareAddr(arpPacket.SourceHwAddress).String())
				}
			}
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcpPacket, _ := tcpLayer.(*layers.TCP)
				if ip, ok := s.SeqMap.Load(tcpPacket.Ack - 1); ok {
					ipStr := ip.(string)
					if _, exists := s.ResultMap[ipStr]; !exists {
						s.ResultMap[ipStr] = make(map[uint16]struct{})
					}
					if _, exists := s.ResultMap[ipStr][uint16(tcpPacket.SrcPort)]; !exists {
						//gologger.Info().Msgf("%v:%v", ipStr, uint16(tcpPacket.SrcPort))
						s.ResultMap[ipStr][uint16(tcpPacket.SrcPort)] = struct{}{}
					}
					s.sendRST(ipStr, tcpPacket)
				}
			}
		}
	}
}

func (s *Scan) Cancel() {
	time.Sleep(time.Duration(s.allWait) * time.Second)
	s.cancel()
}

func (s *Scan) GetResult() map[string]map[uint16]struct{} {
	for ip, _ := range s.ResultMap {
		if _, exits := s.FirewallsMap[ip]; exits {
			gologger.Info().Msgf("%v 开放端口数量 > 500, 可能存在防火墙 !", ip)
			delete(s.ResultMap, ip)
		}
	}
	return s.ResultMap
}

func (s *Scan) WaitAndClose() *Scan {
	s.wg.Wait()
	if os.Getenv("GOOS") != "windows" {
		eth := layers.Ethernet{
			SrcMAC:       macStrToMac(s.NetWorkBaseInfo.SrcMac),
			DstMAC:       macStrToMac(s.NetWorkBaseInfo.SrcMac),
			EthernetType: layers.EthernetTypeARP,
		}
		arp := layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         layers.ARPReply,
			SourceHwAddress:   []byte(macStrToMac(s.NetWorkBaseInfo.SrcMac)),
			SourceProtAddress: []byte(ipStrToIPv4(s.NetWorkBaseInfo.SrcIP)),
			DstHwAddress:      []byte(macStrToMac(s.NetWorkBaseInfo.SrcMac)),
			DstProtAddress:    []byte(ipStrToIPv4(s.NetWorkBaseInfo.SrcIP)),
		}
		handle, _ := pcap.OpenLive(s.NetWorkBaseInfo.DeviceName, 1024, false, time.Second)
		buffer := s.bufferPool.Get().(gopacket.SerializeBuffer)
		defer func() {
			handle.Close()
			err := buffer.Clear()
			if err != nil {
				gologger.Error().Msgf("buf.Clear() error : %v", err)
			}
			s.bufferPool.Put(buffer)
		}()
		err := gopacket.SerializeLayers(buffer, s.SerializeOptions, &eth, &arp)
		if err != nil {
			gologger.Error().Msgf("gopacket.SerializeLayers error : %v", err.Error())
		}
		err = handle.WritePacketData(buffer.Bytes())
		if err != nil {
			gologger.Error().Msgf("Handle.WritePacketData(buffer.Bytes()[:42]) error : %v", err)
		}
	}
	s.Handle.Close()
	err := s.bar.Close()
	if err != nil {
		gologger.Error().Msg(err.Error())
		return s
	}
	return s
}
