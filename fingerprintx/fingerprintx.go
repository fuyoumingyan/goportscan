package fingerprintx

import (
	"github.com/fuyoumingyan/utils/limiter"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/scan"
	"github.com/projectdiscovery/gologger"
	"net/netip"
	"strings"
	"time"
)

type FingerPrint struct {
	Targets  []plugins.Target
	Results  []*plugins.Service
	netIpMap map[string]netip.Addr
	config   scan.Config
	wg       *limiter.Limiter
}

// NewFingerPrint 指纹识别
// show => 进度条跑完之后是否还显示
// limitNum => 并发限制
func NewFingerPrint(portInfoMap map[string]map[uint16]struct{}, limitNum int) *FingerPrint {
	f := new(FingerPrint)
	f.wg = limiter.New(limitNum)
	for ip, ports := range portInfoMap {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		for port := range ports {
			f.Targets = append(f.Targets, plugins.Target{
				Address: netip.AddrPortFrom(addr, port),
			})
		}
	}
	f.config = scan.Config{
		DefaultTimeout: time.Duration(2) * time.Second,
		FastMode:       false,
		Verbose:        false,
		UDP:            false,
	}
	return f
}

func (f *FingerPrint) getSingleFingerPrint(scanTarget plugins.Target) {
	defer f.wg.Done()
	result, err := f.config.SimpleScanTarget(scanTarget)
	if err == nil && result != nil {
		f.Results = append(f.Results, result)
	}
}

func (f *FingerPrint) GetFingerPrints() *FingerPrint {
	for _, scanTarget := range f.Targets {
		f.wg.Add()
		go f.getSingleFingerPrint(scanTarget)
	}
	f.wg.WaitAndClose()
	return f
}

type Service struct {
	Port     uint16
	Protocol string
}

func (f *FingerPrint) GetResultMap() map[string][]Service {
	var serviceMap = make(map[string][]Service, len(f.Results))
	for _, result := range f.Results {
		var service = Service{
			Port:     uint16(result.Port),
			Protocol: strings.ToLower(result.Protocol),
		}
		if services, exists := serviceMap[result.IP]; !exists {
			serviceMap[result.IP] = []Service{service}
		} else {
			serviceMap[result.IP] = append(services, service)
		}
	}
	return serviceMap
}
