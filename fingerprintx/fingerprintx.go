package fingerprintx

import (
	"github.com/fuyoumingyan/utils/progress"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/scan"
	"github.com/projectdiscovery/gologger"
	"github.com/schollz/progressbar/v3"
	"net/netip"
	"strings"
	"time"
)

type FingerPrint struct {
	Targets  []plugins.Target
	Results  []*plugins.Service
	netIpMap map[string]netip.Addr
	config   scan.Config
	bar      *progressbar.ProgressBar
}

func NewFingerPrint(portInfoMap map[string]map[uint16]struct{}, show bool) *FingerPrint {
	f := new(FingerPrint)
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
	f.bar = progress.NewProgressbar(int64(len(f.Targets)), "指纹识别", show)
	f.config = scan.Config{
		DefaultTimeout: time.Duration(2) * time.Second,
		FastMode:       false,
		Verbose:        false,
		UDP:            false,
	}
	return f
}

func (f *FingerPrint) getSingleFingerPrint(scanTarget plugins.Target) {
	defer func() {
		err := f.bar.Add(1)
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
	}()
	result, err := f.config.SimpleScanTarget(scanTarget)
	if err == nil && result != nil {
		f.Results = append(f.Results, result)
	}
}

func (f *FingerPrint) GetFingerPrints() *FingerPrint {
	for _, scanTarget := range f.Targets {
		f.getSingleFingerPrint(scanTarget)
	}
	err := f.bar.Finish()
	if err != nil {
		gologger.Error().Msg(err.Error())
		return f
	}
	err = f.bar.Close()
	if err != nil {
		gologger.Error().Msg(err.Error())
		return f
	}
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
